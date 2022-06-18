mod consts;

fn next_u32_wrap(buf: &[u8], offset: &mut usize) -> u32 {
    let mut v = 0;

    for _ in 0..4 {
        if *offset >= buf.len() {
            *offset = 0;
        }

        let broke: i8 = buf[*offset] as i8;

        v = (v << 8) | (broke as u32) as u32;
        *offset += 1;
    }

    v
}

pub struct Brokefish {
    s: [[u32; 256]; 4],
    p: [u32; 18],
}

impl Brokefish {
    pub fn new(key: &[u8]) -> Brokefish {
        let mut bf = Brokefish {
            s: consts::S,
            p: consts::P,
        };

        bf.expand_key(key);
        bf
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            let next_u32 = next_u32_wrap(key, &mut key_pos);
            self.p[i] ^= next_u32;
        }

        let mut lr = [0u32; 2];
        for i in 0..9 {
            lr = self.encrypt_block(lr);
            self.p[2 * i] = lr[0];
            self.p[2 * i + 1] = lr[1];
        }

        for i in 0..4 {
            for j in 0..128 {
                lr = self.encrypt_block(lr);
                self.s[i][2 * j] = lr[0];
                self.s[i][2 * j + 1] = lr[1];
            }
        }
    }

    fn round_function(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 0xff) as usize];
        let c = self.s[2][((x >> 8) & 0xff) as usize];
        let d = self.s[3][(x & 0xff) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt_block(&self, [mut l, mut r]: [u32; 2]) -> [u32; 2] {
        for i in 0..8 {
            l ^= self.p[2 * i];
            r ^= self.round_function(l);
            r ^= self.p[2 * i + 1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];

        [r, l]
    }

    fn decrypt_block(&self, [mut l, mut r]: [u32; 2]) -> [u32; 2] {
        for i in (1..9).rev() {
            l ^= self.p[2 * i + 1];
            r ^= self.round_function(l);
            r ^= self.p[2 * i];
            l ^= self.round_function(r);
        }
        l ^= self.p[1];
        r ^= self.p[0];

        [r, l]
    }

    pub fn encrypt(&self, data: &[u8]) -> &[u8] {
        todo!()
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let padded_length = if data.len() % 8 == 0 {
            data.len()
        } else {
            data.len() + (8 - (data.len() % 8))
        };

        let mut buf: Vec<u8> = vec![0; padded_length];
        for i in (0..padded_length).step_by(8) {
            let mut l = u32::from_le_bytes(data[i..i + 4].try_into().expect("couldn't get l"));
            let mut r = u32::from_le_bytes(data[i + 4..i + 8].try_into().expect("couldn't get r"));
            [l, r] = self.decrypt_block([l, r]);

            buf[i..i + 4].copy_from_slice(&l.to_le_bytes());
            buf[i + 4..i + 8].copy_from_slice(&r.to_le_bytes());
        }

        buf
    }
}
