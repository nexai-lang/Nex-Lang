use std::io;

pub trait PalTcpStream: Send {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

pub trait Pal: Send + Sync {
    fn fs_read(&self, path: &str) -> io::Result<Vec<u8>>;
    fn fs_write(&self, path: &str, data: &[u8]) -> io::Result<()>;
    fn tcp_connect(&self, host: &str, port: u16) -> io::Result<Box<dyn PalTcpStream>>;
}

#[cfg(unix)]
mod imp {
    use super::{Pal, PalTcpStream};
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;

    pub struct OsPal;

    impl OsPal {
        #[inline]
        pub const fn new() -> Self {
            Self
        }
    }

    struct OsTcpStream {
        inner: TcpStream,
    }

    impl PalTcpStream for OsTcpStream {
        fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.inner.write_all(data)
        }

        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Pal for OsPal {
        fn fs_read(&self, path: &str) -> io::Result<Vec<u8>> {
            fs::read(path)
        }

        fn fs_write(&self, path: &str, data: &[u8]) -> io::Result<()> {
            fs::write(path, data)
        }

        fn tcp_connect(&self, host: &str, port: u16) -> io::Result<Box<dyn PalTcpStream>> {
            let inner = TcpStream::connect((host, port))?;
            Ok(Box::new(OsTcpStream { inner }))
        }
    }

    pub fn default_pal() -> Box<dyn Pal> {
        Box::new(OsPal::new())
    }
}

#[cfg(windows)]
mod imp {
    use super::{Pal, PalTcpStream};
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;

    pub struct OsPal;

    impl OsPal {
        #[inline]
        pub const fn new() -> Self {
            Self
        }
    }

    struct OsTcpStream {
        inner: TcpStream,
    }

    impl PalTcpStream for OsTcpStream {
        fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.inner.write_all(data)
        }

        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Pal for OsPal {
        fn fs_read(&self, path: &str) -> io::Result<Vec<u8>> {
            fs::read(path)
        }

        fn fs_write(&self, path: &str, data: &[u8]) -> io::Result<()> {
            fs::write(path, data)
        }

        fn tcp_connect(&self, host: &str, port: u16) -> io::Result<Box<dyn PalTcpStream>> {
            let inner = TcpStream::connect((host, port))?;
            Ok(Box::new(OsTcpStream { inner }))
        }
    }

    pub fn default_pal() -> Box<dyn Pal> {
        Box::new(OsPal::new())
    }
}

pub fn default_pal() -> Box<dyn Pal> {
    imp::default_pal()
}
