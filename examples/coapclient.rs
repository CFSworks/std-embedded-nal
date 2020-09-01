/// A brutally oversimplified CoAP client that GETs /.well-known/core from localhost:5683

use embedded_nal::nb::block;

fn run<S: embedded_nal::UdpStack + embedded_nal::Dns>(stack: &S) -> Result<(), <S as embedded_nal::UdpStack>::Error>
where
    <S as embedded_nal::UdpStack>::Error: std::convert::From<<S as embedded_nal::Dns>::Error>
{
    let target = embedded_nal::SocketAddr::new(stack.gethostbyname("localhost", embedded_nal::AddrType::IPv6)?, 5683);

    let mut sock = stack.open(target, embedded_nal::Mode::Blocking)?;
    // It's opened in blocking mode, so we're not really expecting WouldBlock, but this gets us rid
    // of the additional error type and allows `?` returns.
    //
    // Data, V1 NON no token, GET, message ID 0x0000, 2x Uri-Path
    block!(stack.write(&mut sock, b"\x50\x01\0\0\xbb.well-known\x04core"))?;

    let mut respbuf = [0; 1500];
    let resplen = block!(stack.read(&mut sock, &mut respbuf))?;
    let response = &respbuf[..resplen];

    println!("Response: {}", String::from_utf8_lossy(response));

    Ok(())
}

fn main() {
    let stack = &std_embedded_nal::STACK;

    run(stack).expect("Error running the main program")
}
