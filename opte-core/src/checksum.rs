pub struct HeaderChecksum {
    inner: [u8; 2],
}

impl HeaderChecksum {
    /// Return the bytes that represent this header checksum.
    pub fn bytes(&self) -> [u8; 2] {
        self.inner
    }

    /// Wrap raw bytes that represent a header checksum.
    ///
    /// NOTE: This could just as well be a `From<[u8; 2]>`
    /// implementation, but the "wrap" verbage is meant to make it
    /// clear that we are wrapping a pair of bytes which represent a
    /// header checksum -- i.e., the one's complement of a one's
    /// complement sum.
    pub fn wrap(hc: [u8; 2]) -> Self {
        Self { inner: hc }
    }
}

impl From<Checksum> for HeaderChecksum {
    fn from(mut csum: Checksum) -> HeaderChecksum {
        Self {
            inner: (!u16::from_ne_bytes(csum.bytes())).to_ne_bytes()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Checksum {
    inner: u32,
}

impl Checksum {
    pub fn add(&mut self, bytes: &[u8]) {
        self.inner = csum_add(self.inner, bytes);
    }

    pub fn bytes(&mut self) -> [u8; 2] {
        self.finalize()
    }

    pub fn compute(bytes: &[u8]) -> Self {
        Self {
            inner: csum_add(0, bytes),
        }
    }

    pub fn sub(&mut self, bytes: &[u8]) {
        self.inner = csum_sub(self.inner, bytes);
    }

    pub fn finalize(&mut self) -> [u8; 2] {
        while (self.inner >> 16) != 0 {
            self.inner = (self.inner >> 16) + (self.inner & 0xFFFF);
        }

        ((self.inner & 0xFFFF) as u16).to_ne_bytes()
    }
}

impl From<HeaderChecksum> for Checksum {
    fn from(hc: HeaderChecksum) -> Self {
        Self {
            inner: (!u16::from_ne_bytes(hc.bytes())) as u32,
        }
    }
}

impl From<u32> for Checksum {
    fn from(csum: u32) -> Self {
        Self { inner: csum }
    }
}

impl core::ops::Add for Checksum {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self { inner: self.inner + other.inner }
    }
}

impl core::ops::AddAssign for Checksum {
    fn add_assign(&mut self, other: Self) {
        self.inner += other.inner
    }
}

fn csum_add(mut csum: u32, bytes: &[u8]) -> u32 {
    let mut len = bytes.len();
    let mut pos = 0;

    while len > 1 {
        csum += (u16::from_ne_bytes([bytes[pos], bytes[pos + 1]])) as u32;
        pos += 2;
        len -= 2;
    }

    if len == 1 {
        csum += bytes[pos] as u32;
    }

    csum
}

pub fn csum_sub(mut csum: u32, bytes: &[u8]) -> u32 {
    let mut len = bytes.len();
    let mut pos = 0;

    while len > 1 {
        let sub = (!u16::from_ne_bytes([bytes[pos], bytes[pos + 1]])) as u32;
        csum += sub;
        pos += 2;
        len -= 2;
    }

    if len == 1 {
        csum += (!bytes[pos]) as u32;
    }

    csum
}
