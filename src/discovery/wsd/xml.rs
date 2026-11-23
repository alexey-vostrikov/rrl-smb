//! Reading the few SOAP envelopes the server answers, and escaping text
//! for the ones it writes.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::{Namespace, QName, ResolveResult};
use quick_xml::reader::NsReader;

pub(super) const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
pub(super) const WSA: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub(super) const WSD: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

/// Longest field, in characters: DPWS lets receivers reject longer ones.
const MAX_FIELD_CHARS: usize = 256;
/// Most names in a Types or values in a Scopes list.
const MAX_TOKENS: usize = 32;
/// Deepest element nesting.
const MAX_DEPTH: usize = 16;
/// Most elements in one envelope.
const MAX_ELEMENTS: usize = 256;
/// Most namespace declarations in scope at once.
const MAX_BINDINGS: usize = 32;

/// Why an envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Malformed(pub(super) &'static str);

/// A qualified name in element content: a namespace, `None` when the name
/// has no prefix and no default namespace applies, and a local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Name {
    pub(super) namespace: Option<String>,
    pub(super) local: String,
}

/// The parts of a SOAP 1.2 envelope the server reads.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Envelope {
    pub(super) action: Option<String>,
    pub(super) message_id: Option<String>,
    pub(super) to: Option<String>,
    /// Address of `wsa:ReplyTo`.
    pub(super) reply_to: Option<String>,
    pub(super) body: Body,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum Body {
    /// No Body element, or one without children.
    #[default]
    Empty,
    /// `wsd:Probe`. `None` for an absent list.
    Probe {
        types: Option<Vec<Name>>,
        scopes: Option<Vec<String>>,
    },
    /// `wsd:Resolve`, with the address of its endpoint reference.
    Resolve { address: Option<String> },
    /// Any other element.
    Other,
}

/// Elements the reader knows, by their place in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Envelope,
    Header,
    Body,
    Action,
    MessageId,
    To,
    ReplyTo,
    ReplyToAddress,
    Probe,
    Types,
    Scopes,
    Resolve,
    Endpoint,
    EndpointAddress,
    Other,
}

impl Tag {
    /// Whether the text of the element is read.
    fn has_text(self) -> bool {
        matches!(
            self,
            Tag::Action
                | Tag::MessageId
                | Tag::To
                | Tag::ReplyToAddress
                | Tag::Types
                | Tag::Scopes
                | Tag::EndpointAddress
        )
    }
}

/// Parses a SOAP 1.2 envelope. Rejects anything that is not well-formed,
/// document type declarations, processing instructions, entity references
/// other than the predefined ones, a header field or body given twice,
/// and input past the limits on depth, elements, namespace declarations,
/// field length and list length.
pub(super) fn parse(text: &str) -> Result<Envelope, Malformed> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(MAX_BINDINGS);
    // The reader's state lives in one place: the envelope being filled, the path of elements opened
    // so far, and the counters the limits are checked against. Splitting it out of the loop is what
    // keeps each step small enough to read — the loop itself only decides *which* step a tag is.
    let mut scan = Scan::default();
    loop {
        if let Some(envelope) = step(&mut reader, &mut scan)? {
            return Ok(envelope);
        }
    }
}

/// One event off the reader, applied to `scan`; the envelope once the document has ended.
fn step(reader: &mut NsReader<&[u8]>, scan: &mut Scan) -> Result<Option<Envelope>, Malformed> {
    let event = reader
        .read_event()
        .map_err(|_| Malformed("not well-formed XML"))?;
    match &event {
        // An element that opens, and one that opens and closes: the same work, and `empty` is the
        // only difference.
        Event::Start(start) => scan.open(reader, start, false)?,
        Event::Empty(start) => scan.open(reader, start, true)?,
        Event::End(_) => scan.close(reader)?,
        // Everything else — text, references, declarations, the end of the document — is one step
        // in `next`, so that this function stays a dispatcher over three cases.
        other => return scan.next(other),
    }
    Ok(None)
}

/// The parser's state between events.
#[derive(Debug, Default)]
struct Scan {
    envelope: Envelope,
    /// The elements opened and not yet closed, outermost first.
    path: Vec<Tag>,
    /// The characters of the field being read, if the current element has text.
    field: String,
    elements: usize,
    body_children: usize,
    root_seen: bool,
    /// Whether any event has been read yet. A declaration may appear only before the first one, and
    /// this is `false` from `Default`, which is the state of a parser that has read nothing.
    seen_any: bool,
}

impl Scan {
    /// Opens `start`, and closes it again when it is empty.
    ///
    /// The limits are checked before anything is written, so a refused document leaves the envelope
    /// exactly as the previous event did rather than half extended.
    /// Counts the element and refuses one that breaks a limit.
    ///
    /// The root check is here rather than in `open` because it belongs with the counters: an
    /// envelope with two roots is over a limit of one, and keeping the two rules apart is how the
    /// third one gets forgotten.
    fn check_limits(&mut self) -> Result<(), Malformed> {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            return Err(Malformed("too many elements"));
        }
        if self.path.len() >= MAX_DEPTH {
            return Err(Malformed("nested too deep"));
        }
        if self.path.is_empty() && self.root_seen {
            return Err(Malformed("more than one root element"));
        }
        self.root_seen = true;
        Ok(())
    }

    fn open(
        &mut self,
        reader: &NsReader<&[u8]>,
        start: &BytesStart<'_>,
        empty: bool,
    ) -> Result<(), Malformed> {
        self.check_limits()?;
        let parent = self.path.last().copied();
        let tag = tag_of(reader, parent, start)?;
        if parent == Some(Tag::Body) {
            self.body_children += 1;
            if self.body_children > 1 {
                return Err(Malformed("more than one element in the body"));
            }
        }
        begin(&mut self.envelope, parent, tag)?;
        self.path.push(tag);
        if tag.has_text() {
            self.field.clear();
        }
        if empty {
            self.close(reader)?;
        }
        Ok(())
    }

    fn close(&mut self, reader: &NsReader<&[u8]>) -> Result<(), Malformed> {
        end(reader, &mut self.envelope, &mut self.path, &mut self.field)
    }

    /// One event that is neither an opening nor a closing element; the envelope when the document
    /// has ended.
    fn next(&mut self, event: &Event<'_>) -> Result<Option<Envelope>, Malformed> {
        match event {
            Event::Text(text) => self.text(&text.xml10_content())?,
            Event::CData(data) => self.text(&data.xml10_content())?,
            Event::GeneralRef(reference) => self.reference(reference)?,
            // Everything that is markup rather than content: declarations, processing
            // instructions, comments, and the end of the document.
            markup => return self.markup(markup),
        }
        Ok(None)
    }

    /// Adds the character a predefined or numeric reference names.
    ///
    /// Anything else is refused by `resolve_reference`: an entity declared in a document type is
    /// exactly what this reader does not expand, and expanding it would be the parser's half of an
    /// entity-expansion attack.
    fn reference(&mut self, reference: &BytesRef<'_>) -> Result<(), Malformed> {
        let c = resolve_reference(reference)?;
        self.text(c.encode_utf8(&mut [0; 4]))
    }

    /// One markup event, and the envelope when the document has ended.
    fn markup(&mut self, event: &Event<'_>) -> Result<Option<Envelope>, Malformed> {
        let at_start = !std::mem::replace(&mut self.seen_any, true);
        match event {
            // A declaration is allowed exactly once, before anything else.
            Event::Decl(_) if at_start => {}
            // A processing instruction is refused because nothing this server reads is one, and a
            // document type declaration because it can declare entities.
            Event::Decl(_) | Event::PI(_) => return Err(Malformed("processing instruction")),
            Event::DocType(_) => return Err(Malformed("document type declaration")),
            Event::Comment(_) => {}
            Event::Eof => {
                if !self.root_seen || !self.path.is_empty() {
                    return Err(Malformed("incomplete document"));
                }
                return Ok(Some(std::mem::take(&mut self.envelope)));
            }
            // Opening and closing elements are handled by the loop, which is where the reader is.
            Event::Start(_)
            | Event::Empty(_)
            | Event::End(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::GeneralRef(_) => {}
        }
        Ok(None)
    }

    /// Adds characters, refusing text outside the root element.
    fn text(&mut self, content: &str) -> Result<(), Malformed> {
        if self.path.is_empty() {
            if !content.trim().is_empty() {
                return Err(Malformed("text outside the root element"));
            }
        } else if reading(&self.path) {
            push_text(&mut self.field, content)?;
        }
        Ok(())
    }
}

/// Whether text at `path` belongs to a field being read.
fn reading(path: &[Tag]) -> bool {
    path.last().is_some_and(|tag| tag.has_text())
}

fn push_text(field: &mut String, text: &str) -> Result<(), Malformed> {
    if field.chars().count() + text.chars().count() > MAX_FIELD_CHARS {
        return Err(Malformed("field too long"));
    }
    field.push_str(text);
    Ok(())
}

/// The character a reference stands for: a character reference to a
/// character XML allows, or one of the five predefined entities.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, Malformed> {
    if reference.is_char_ref() {
        return match reference.resolve_char_ref() {
            Ok(Some(c)) if is_xml_char(c) => Ok(c),
            _ => Err(Malformed("bad character reference")),
        };
    }
    match &**reference {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(Malformed("undeclared entity")),
    }
}

/// Whether XML 1.0 allows `c` in a document.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

fn namespace_of<'r>(
    reader: &'r NsReader<&[u8]>,
    name: QName<'_>,
) -> Result<Option<&'r str>, Malformed> {
    match reader.resolver().resolve_element(name).0 {
        ResolveResult::Bound(Namespace(ns)) => Ok(Some(ns)),
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Unknown(_) => Err(Malformed("undeclared namespace prefix")),
    }
}

/// Which elements the reader knows, by the element they sit under, their namespace and their name.
///
/// A table rather than a `match`: the answer is pure data, and every name added to the protocol adds
/// a row instead of a branch. Two rows are absent on purpose — the root, which is refused when it is
/// not this one, and `Address` under `ReplyTo` versus under `EndpointReference`, which the parent
/// column already tells apart.
const KNOWN: &[(Option<Tag>, &str, &str, Tag)] = &[
    (None, SOAP, "Envelope", Tag::Envelope),
    (Some(Tag::Envelope), SOAP, "Header", Tag::Header),
    (Some(Tag::Envelope), SOAP, "Body", Tag::Body),
    (Some(Tag::Header), WSA, "Action", Tag::Action),
    (Some(Tag::Header), WSA, "MessageID", Tag::MessageId),
    (Some(Tag::Header), WSA, "To", Tag::To),
    (Some(Tag::Header), WSA, "ReplyTo", Tag::ReplyTo),
    (Some(Tag::ReplyTo), WSA, "Address", Tag::ReplyToAddress),
    (Some(Tag::Body), WSD, "Probe", Tag::Probe),
    (Some(Tag::Body), WSD, "Resolve", Tag::Resolve),
    (Some(Tag::Probe), WSD, "Types", Tag::Types),
    (Some(Tag::Probe), WSD, "Scopes", Tag::Scopes),
    (Some(Tag::Resolve), WSA, "EndpointReference", Tag::Endpoint),
    (Some(Tag::Endpoint), WSA, "Address", Tag::EndpointAddress),
];

/// The tag of element `start` under an element tagged `parent`.
fn tag_of(
    reader: &NsReader<&[u8]>,
    parent: Option<Tag>,
    start: &BytesStart<'_>,
) -> Result<Tag, Malformed> {
    let ns = namespace_of(reader, start.name())?;
    let local = start.local_name();
    let local: &str = local.as_ref();
    let known = KNOWN.iter().find(|(under, namespace, name, _)| {
        *under == parent && Some(*namespace) == ns && *name == local
    });
    if let Some((_, _, _, tag)) = known {
        return Ok(*tag);
    }
    // An element at the root that is not a SOAP envelope: the document is something else, and
    // answering "unknown element" would make the caller look for a body that is not there.
    if parent.is_none() {
        return Err(Malformed("not a SOAP 1.2 envelope"));
    }
    Ok(Tag::Other)
}

/// Takes note of element `tag` starting under `parent`, rejecting a field
/// given twice.
/// Whether the field `tag` fills is already filled.
///
/// A SOAP header field given twice is a malformed envelope, not a later value winning: a reader that
/// took the last one would answer a request that says two different things.
fn already_present(envelope: &Envelope, tag: Tag) -> bool {
    match tag {
        Tag::Action => envelope.action.is_some(),
        Tag::MessageId => envelope.message_id.is_some(),
        Tag::To => envelope.to.is_some(),
        Tag::ReplyToAddress => envelope.reply_to.is_some(),
        Tag::Types => matches!(envelope.body, Body::Probe { types: Some(_), .. }),
        Tag::Scopes => matches!(
            envelope.body,
            Body::Probe {
                scopes: Some(_),
                ..
            }
        ),
        Tag::EndpointAddress => matches!(envelope.body, Body::Resolve { address: Some(_) }),
        _ => false,
    }
}

fn begin(envelope: &mut Envelope, parent: Option<Tag>, tag: Tag) -> Result<(), Malformed> {
    if already_present(envelope, tag) {
        return Err(Malformed("element given twice"));
    }
    match tag {
        Tag::Probe => {
            envelope.body = Body::Probe {
                types: None,
                scopes: None,
            }
        }
        Tag::Resolve => envelope.body = Body::Resolve { address: None },
        Tag::Other if parent == Some(Tag::Body) => envelope.body = Body::Other,
        _ => {}
    }
    Ok(())
}

/// Ends the innermost element, storing the field read in it. Runs before
/// the reader leaves the element's namespace scope, so that names in
/// The names in a `Types` list, each with the namespace its prefix resolves to.
///
/// The names of a `Types` list, each with the namespace its prefix resolves to.
///
/// Types resolve with the declarations in force there. A prefix that is not declared is refused
/// rather than taken literally: a client that sent one
/// meant something this reader cannot see, and answering it as an unknown type would answer a
/// question it did not ask.
fn qualified_names(reader: &NsReader<&[u8]>, text: &str) -> Result<Vec<Name>, Malformed> {
    tokens(text)?
        .map(|token| {
            let ns = namespace_of(reader, QName(token))?;
            let local = token.rsplit(':').next().unwrap_or(token);
            Ok(Name {
                namespace: ns.map(str::to_string),
                local: local.to_string(),
            })
        })
        .collect()
}

/// The values of a `Scopes` list, trimmed of nothing but the separators `tokens` already removes.
fn scope_values(text: &str) -> Result<Vec<String>, Malformed> {
    Ok(tokens(text)?.map(str::to_string).collect())
}

/// Fills the field `tag` names when it is one of the plain text fields; `false` when it is not.
///
/// The four are the same assignment under different names, and grouping them is what keeps the
/// caller's `match` to the three that need the reader or a second pass over the text.
fn plain_field(envelope: &mut Envelope, tag: Tag, text: &str) -> bool {
    match tag {
        Tag::Action => envelope.action = Some(text.to_string()),
        Tag::MessageId => envelope.message_id = Some(text.to_string()),
        Tag::To => envelope.to = Some(text.to_string()),
        Tag::ReplyToAddress => envelope.reply_to = Some(text.to_string()),
        _ => return false,
    }
    true
}

fn end(
    reader: &NsReader<&[u8]>,
    envelope: &mut Envelope,
    path: &mut Vec<Tag>,
    field: &mut String,
) -> Result<(), Malformed> {
    let Some(tag) = path.pop() else {
        return Err(Malformed("unbalanced end tag"));
    };
    if !tag.has_text() {
        return Ok(());
    }
    let text = std::mem::take(field);
    let text = text.trim();
    // The four header fields are one assignment each; the rest need the reader or a second pass.
    if plain_field(envelope, tag, text) {
        return Ok(());
    }
    fill(envelope, tag, text, reader)
}

/// Puts the text of element `tag` where the envelope wants it.
///
/// The closing tag is where a field's text is complete, so this is where the three that need more
/// than the text are handled: the endpoint address inside `Resolve`, and the two lists inside
/// `Probe`. A list that fails to parse refuses the whole envelope rather than storing half of it.
fn fill(
    envelope: &mut Envelope,
    tag: Tag,
    text: &str,
    reader: &NsReader<&[u8]>,
) -> Result<(), Malformed> {
    match tag {
        Tag::EndpointAddress => {
            if let Body::Resolve { address } = &mut envelope.body {
                *address = Some(text.to_string());
            }
        }
        // The two lists share an element in `Probe` and differ only in what each token becomes.
        Tag::Types | Tag::Scopes => probe_list(envelope, tag, text, reader)?,
        _ => {}
    }
    Ok(())
}

/// Stores one of the `Probe` lists, whether its tokens are qualified names or plain values.
///
/// A list that fails to parse refuses the envelope: storing what was read before the bad token would
/// answer a probe that asked for less than it meant.
fn probe_list(
    envelope: &mut Envelope,
    tag: Tag,
    text: &str,
    reader: &NsReader<&[u8]>,
) -> Result<(), Malformed> {
    let Body::Probe { types, scopes } = &mut envelope.body else {
        return Ok(());
    };
    if tag == Tag::Types {
        *types = Some(qualified_names(reader, text)?);
    } else {
        *scopes = Some(scope_values(text)?);
    }
    Ok(())
}

/// The whitespace-separated tokens of `text`, at most [`MAX_TOKENS`].
fn tokens(text: &str) -> Result<std::str::SplitWhitespace<'_>, Malformed> {
    if text.split_whitespace().count() > MAX_TOKENS {
        return Err(Malformed("list too long"));
    }
    Ok(text.split_whitespace())
}

/// `text` escaped for element content and attribute values. Characters
/// XML cannot carry become U+FFFD.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if is_xml_char(c) => out.push(c),
            _ => out.push('\u{fffd}'),
        }
    }
    out
}
