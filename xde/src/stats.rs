use opte::api::Direction;
use opte::ddi::kstat::KStatProvider;
use opte::ddi::kstat::KStatU64;
use opte::engine::packet::ParseError;
use opte::ingot::types::ParseError as IngotError;

/// Top-level KStats for XDE.
#[derive(KStatProvider)]
pub struct XdeStats {
    /// The number of inbound packets dropped as explicitly
    /// rejected during parsing.
    in_drop_reject: KStatU64,
    /// The number of inbound packets dropped with an unexpected
    /// protocol number.
    in_drop_unwanted_proto: KStatU64,
    /// The number of inbound packets dropped for having
    /// insufficient bytes to read the standard set of headers.
    in_drop_truncated: KStatU64,
    /// The number of inbound packets dropped due to a header being
    /// split across `mblk_t` boundaries.
    in_drop_straddled: KStatU64,
    /// The number of inbound packets dropped due to having an illegal
    /// value in a mandatory/critical field.
    in_drop_illegal_val: KStatU64,
    /// The number of inbound packets dropped due to reporting more
    /// bytes than the packet contains.
    in_drop_bad_len: KStatU64,
    /// The number of inbound packets dropped due to the presence of
    /// unrecognised critical options.
    in_drop_bad_tun_opt: KStatU64,
    /// The number of inbound packets dropped for other reasons, including
    /// parser programming errors.
    in_drop_misc: KStatU64,

    /// The number of outbound packets dropped as explicitly
    /// rejected during parsing.
    out_drop_reject: KStatU64,
    /// The number of outbound packets dropped with an unexpected
    /// protocol number.
    out_drop_unwanted_proto: KStatU64,
    /// The number of outbound packets dropped for having
    /// insufficient bytes to read the standard set of headers.
    out_drop_truncated: KStatU64,
    /// The number of outbound packets dropped due to a header being
    /// split across `mblk_t` boundaries.
    out_drop_straddled: KStatU64,
    /// The number of outbound packets dropped due to having an illegal
    /// value in a mandatory/critical field.
    out_drop_illegal_val: KStatU64,
    /// The number of outbound packets dropped due to reporting more
    /// bytes than the packet contains.
    out_drop_bad_len: KStatU64,
    /// The number of outbound packets dropped for other reasons, including
    /// parser programming errors.
    out_drop_misc: KStatU64,
    // NOTE: tun_opt is not relevant to outbound packets -- no encapsulation
    // is in use.
}

impl XdeStats {
    pub fn parse_error(&mut self, dir: Direction, err: &ParseError) {
        use Direction::*;
        match (dir, err) {
            (In, ParseError::IngotError(e)) => match e.error() {
                IngotError::Unwanted => self.in_drop_unwanted_proto += 1,
                IngotError::TooSmall | IngotError::NoRemainingChunks => {
                    self.in_drop_truncated += 1
                }
                IngotError::StraddledHeader => self.in_drop_straddled += 1,
                IngotError::Reject => self.in_drop_reject += 1,
                IngotError::IllegalValue => self.in_drop_illegal_val += 1,
                IngotError::NeedsHint | IngotError::CannotAccept => {
                    self.in_drop_misc += 1
                }
            },
            (In, ParseError::IllegalValue(_)) => self.in_drop_illegal_val += 1,
            (In, ParseError::BadLength(_)) => self.in_drop_bad_len += 1,
            (In, ParseError::UnrecognisedTunnelOpt { .. }) => {
                self.in_drop_bad_tun_opt += 1
            }

            (Out, ParseError::IngotError(e)) => match e.error() {
                IngotError::Unwanted => self.out_drop_unwanted_proto += 1,
                IngotError::TooSmall | IngotError::NoRemainingChunks => {
                    self.out_drop_truncated += 1
                }
                IngotError::StraddledHeader => self.out_drop_straddled += 1,
                IngotError::Reject => self.out_drop_reject += 1,
                IngotError::IllegalValue => self.out_drop_illegal_val += 1,
                IngotError::NeedsHint | IngotError::CannotAccept => {
                    self.out_drop_misc += 1
                }
            },
            (Out, ParseError::IllegalValue(_)) => {
                self.out_drop_illegal_val += 1
            }
            (Out, ParseError::BadLength(_)) => self.out_drop_bad_len += 1,
            (Out, _) => self.out_drop_misc += 1,
        }
    }
}
