// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::fs;
use std::io::BufWriter;
use std::io::Write;

use quiche_apps::args::*;

use quiche_apps::common::*;

use quiche_apps::client::*;

fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(CLIENT_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let mut args = ClientArgs::with_docopt(&docopt);

    // create a log-file
    match args.store_eval{
        Some(ref p) => {
            // Make BufWriter
            let path = format!("{}/client.txt",p);
            let file = fs::OpenOptions::new().create(true).append(true).open(&path);
            match file{
                Ok(v) => {
                    let mut rw = BufWriter::new(v);
                    let text = format!("timestamp;packet-type;stream-id;body-bytes\n");
                    rw.write_all(text.as_bytes()).ok();
                    rw.flush().unwrap();
                },
                Err(_) => (),
            }
        },
        None => (),
    };

    // Add user-agent to the headers
    // quiche::h3::Header::new(b"user-agent", b"quiche"),
    args.req_headers.push(("user-agent: quiche-client").to_string());

    match connect(args, conn_args, stdout_sink) {
        Err(ClientError::HandshakeFail) => std::process::exit(-1),

        Err(ClientError::HttpFail) => std::process::exit(-2),

        Err(ClientError::Other(e)) => panic!("{}", e),

        Ok(_) => info!("Correctly Done!"),
    }
}
