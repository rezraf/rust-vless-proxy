use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::dpi;

/// A wrapper around TcpStream that fragments the first write (TLS ClientHello)
/// into multiple small TCP segments to bypass DPI inspection.
///
/// After the first write is fragmented, all subsequent writes pass through
/// directly without modification.
pub struct FragmentingStream {
    inner: TcpStream,
    /// Buffer for data that needs to be sent in fragments
    pending_fragments: Vec<Vec<u8>>,
    /// Index of current fragment being sent
    current_fragment: usize,
    /// Bytes already written from current fragment
    current_offset: usize,
    /// Whether the first write (ClientHello) has been processed
    first_write_done: AtomicBool,
    /// Fragment size for ClientHello splitting
    fragment_size: usize,
    /// Whether to apply TLS record splitting
    record_split: bool,
    /// Optional fake SNI to inject
    fake_sni: Option<String>,
}

impl FragmentingStream {
    pub fn new(
        stream: TcpStream,
        fragment_size: usize,
        record_split: bool,
        fake_sni: Option<String>,
    ) -> Self {
        Self {
            inner: stream,
            pending_fragments: Vec::new(),
            current_fragment: 0,
            current_offset: 0,
            first_write_done: AtomicBool::new(false),
            fragment_size,
            record_split,
            fake_sni,
        }
    }

    /// Process the first TLS write — fragment it for DPI evasion.
    fn process_first_write(&mut self, data: &[u8]) {
        let mut buf = data.to_vec();

        // Step 1: Replace SNI with fake domain if configured
        if let Some(ref fake) = self.fake_sni {
            if dpi::replace_sni_in_client_hello(&mut buf, fake) {
                tracing::debug!(fake_sni = %fake, "replaced SNI in ClientHello");
            }
        }

        // Step 2: Split TLS record into smaller records
        let records = if self.record_split {
            dpi::split_tls_record(&buf, self.fragment_size)
        } else {
            vec![buf]
        };

        // Step 3: Fragment each record into small TCP segments
        let mut fragments = Vec::new();
        let mut rng = rand::thread_rng();

        for record in &records {
            let mut offset = 0;
            while offset < record.len() {
                let chunk_size =
                    rng.gen_range(1..=self.fragment_size.min(record.len() - offset));
                let end = (offset + chunk_size).min(record.len());
                fragments.push(record[offset..end].to_vec());
                offset = end;
            }
        }

        tracing::debug!(
            original_len = data.len(),
            num_fragments = fragments.len(),
            "fragmented ClientHello for DPI evasion"
        );

        self.pending_fragments = fragments;
        self.current_fragment = 0;
        self.current_offset = 0;
        self.first_write_done.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for FragmentingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // If we have pending fragments to send, drain them first
        if !this.pending_fragments.is_empty() {
            while this.current_fragment < this.pending_fragments.len() {
                let frag = &this.pending_fragments[this.current_fragment];
                let remaining = &frag[this.current_offset..];

                match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                    Poll::Ready(Ok(n)) => {
                        this.current_offset += n;
                        if this.current_offset >= frag.len() {
                            this.current_fragment += 1;
                            this.current_offset = 0;

                            // Flush between fragments to force separate TCP segments
                            match Pin::new(&mut this.inner).poll_flush(cx) {
                                Poll::Ready(Ok(())) => {}
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // All fragments sent — clear
            let total_len = this
                .pending_fragments
                .iter()
                .map(|f| f.len())
                .sum::<usize>();
            this.pending_fragments.clear();
            this.current_fragment = 0;
            this.current_offset = 0;

            // Report that we "consumed" all original bytes
            // The caller passed in `buf` which was the original ClientHello
            return Poll::Ready(Ok(total_len.min(buf.len())));
        }

        // First write? Fragment it for DPI evasion.
        if !this.first_write_done.load(Ordering::SeqCst) {
            this.process_first_write(buf);
            // Now recurse to start sending fragments
            return Pin::new(this).poll_write(cx, buf);
        }

        // Subsequent writes — pass through directly
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
