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
use std::time::SystemTime;
use std::convert::TryInto;

use std::fs;
use std::io;

use std::io::BufWriter;
use std::net;

use std::io::prelude::*;

use std::collections::HashMap;

use std::convert::TryFrom;

use std::rc::Rc;

use std::cell::RefCell;

use quiche::h3::Priority;
use quiche::PathStats;
use ring::rand::*;

use quiche_apps::args::*;

use quiche_apps::common::*;

use quiche_apps::sendto::*;

use std::thread;
// use std::time::Duration;
use std::sync::mpsc;
use quiche::h3::NameValue;

const MAX_BUF_SIZE: usize = 65507;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {

    env_logger::builder().format_timestamp_nanos().init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ServerArgs::with_docopt(&docopt);


    ////////////////////////// Logic for multithreading ///////////////////////////////////////////////////
    // Keep track of the running threads
    let mut handles= Vec::new();
    let (tx,rx) = mpsc::channel::<(String,PartialResponse)>();

    // Thread for communication with data client
    let arguments = args.clone();
    let connection_args = conn_args.clone();
    let handle = thread::spawn(move || {
        rx_api(connection_args, arguments,tx);
    });
    handles.push(handle);

    // Thread for communication with client
    let arguments = args.clone();
    let connection_args = conn_args.clone();
    let handle = thread::spawn(move || {
        tx_api(connection_args, arguments,rx);
    });
    handles.push(handle);


    ////////////////////////// Catch all the running threads //////////////////////////////////////////////
    info!("{} threads running", handles.len());
    // Wait for all the threads to finish
    for handle in handles{
        handle.join().unwrap();
    }
}

////////////////////////////////////////////// RX API /////////////////////////////////////////////////////
fn rx_api(conn_args:CommonArgs,args:ServerArgs, tx:mpsc::Sender<(String,PartialResponse)>){
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];
    let mut pacing = false;
    // Store largest stream_id for goaway case
    let mut largest_stream_id :HashMap<String,u64> = HashMap::new();
    let mut debug_writer: HashMap<String,Option<std::io::BufWriter<std::fs::File>>> = HashMap::new();
    let mut conns_total: HashMap<String,usize> = HashMap::new();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(args.listen_from.parse().unwrap()).unwrap();

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    if !args.disable_pacing {
        match set_txtime_sockopt(&socket) {
            Ok(_) => {
                pacing = true;
                debug!("successfully set SO_TXTIME socket option");
            },
            Err(e) => debug!("setsockopt failed {:?}", e),
        };
    }

    info!("listening on {:}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = if args.disable_gso {
        false
    } else {
        detect_gso(&socket, max_datagram_size)
    };

    trace!("GSO detected: {}", enable_gso);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(&args.cert).unwrap();
    config.load_priv_key_from_pem_file(&args.key).unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);
    config.set_initial_congestion_window_packets(
        usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
    );

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    config.enable_pacing(pacing);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    let mut pkt_count = 0;

    let mut continue_write = false;

    let local_addr = socket.local_addr().unwrap();

    let mut log_writer = match args.store_eval{
        Some(ref p) => {
            // Make BufWriter
            let path = format!("{}/server-rx.txt",p);
            let file = fs::OpenOptions::new().create(true).append(true).open(&path);
            match file{
                Ok(v) => Some(BufWriter::new(v)),
                Err(_) => None,
            }
        },
        None => None,
    };
    // Make header of log file
    match log_writer {
        Some(ref mut w) => {
            let text = format!("timestamp;packet-type;connection-id;a-conn-id;body-bytes\n");
            w.write_all(text.as_bytes()).ok();
            w.flush().unwrap();
        },
        None => (),
    }

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{target_path}/{pkt_count}.pkt");

                if let Ok(f) = std::fs::File::create(path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid) &&
                !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.no_retry {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http_conn: None,
                    client_id,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    app_proto_selected: false,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;

                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&conn_id).unwrap(),
                };

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();

                #[allow(clippy::box_default)]
                if alpns::HTTP_09.contains(&app_proto) {
                    client.http_conn = Some(Box::<Http09Conn>::default());

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(&app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        conn_args.max_field_section_size,
                        conn_args.qpack_max_table_capacity,
                        conn_args.qpack_blocked_streams,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ) {
                        Ok(v) => Some(v),

                        Err(e) => {
                            trace!("{} {}", client.conn.trace_id(), e);
                            None
                        },
                    };

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();
            }

            if client.http_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http_conn.as_mut().unwrap();
                let partial_responses = &mut client.partial_responses;

                // Handle writable streams.
                for stream_id in conn.writable() {
                    http_conn.handle_writable(conn, partial_responses, stream_id);
                }

                // accept request on h3 connection
                match http_conn.get_h3_conn(){
                    Some(h3_conn) => {
                        let large_id = accept_request(h3_conn, conn, &mut buf, &tx,&args.store_rx,&mut debug_writer, &mut log_writer, &mut conns_total);
                        let conn_id = format!("{}",conn.trace_id());
                        largest_stream_id.insert(conn_id.clone(),large_id); 
                    },
                    None => (),
                };
            }

            handle_path_events(client);

            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
                clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimun bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst =
                client.conn.send_quantum().min(client.max_send_burst) /
                    client.max_datagram_size *
                    client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) = match client
                    .conn
                    .send(&mut out[total_write..max_send_burst])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    continue_write = true;
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                break;
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            trace!("{} written {} bytes", client.conn.trace_id(), total_write);

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                for id in c.conn.source_ids() {
                    let id_owned = id.clone().into_owned();
                    clients_ids.remove(&id_owned);
                }
            }

            !c.conn.is_closed()
        });
    }
}
////////////////////////////////////////////// TX API /////////////////////////////////////////////////////

fn tx_api(conn_args:CommonArgs,args:ServerArgs, rx:mpsc::Receiver<(String,PartialResponse)>){
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];
    let mut pacing = false;
    // Stores the current mapping between incoming connection/ device and the stream id to forward the data on
    let mut conn_map: HashMap<String,u64> = HashMap::new();
    // Stores the priorities which can be accessed by policy[index]=stream_id/4, Control stream (id 0) has always highest priority
    let mut policy: Vec<Priority> = Vec::new();
    policy.push(Priority::new(0,false));

    // Initialize policies from json files
    let content_type_policy: HashMap<String,u8> = import_policy_from_json("./policies/content-type.json");
    let device_type_policy: HashMap<String,u8> = import_policy_from_json("./policies/device-type.json");
    let sending_rate_policy: HashMap<String,u8> = import_policy_from_json("./policies/sending-rate.json");

    let feature_weight_list: HashMap<String,u8> = import_policy_from_json("./policies/weights.json");
    let feature_policy_list: HashMap<String,HashMap<String,u8>> = HashMap::from([
        ("Content-type".to_string(), content_type_policy),
        ("Device-type".to_string(), device_type_policy),
        ("Sending-rate".to_string(), sending_rate_policy)
    ]);

    let prioritization = args.prio;
    let no_dropping = args.reliability;
    trace!("No dropping is: {:?}", no_dropping);
    let sending_rate = args.rate;
    let mut producers:HashMap<String,Producer> = HashMap::new();

    // Stores partial responses
    let mut partial_header: HashMap<String, PartialResponse> = HashMap::new();
    // Stores lonly headers
    let mut lonly_headers: HashMap<u64,PartialResponse> = HashMap::new();
    // Stores lonly bodies for later usage
    let mut lonly_bodies: HashMap<u64, PartialResponse> = HashMap::new();

    // Those are primarily for debugging purposes
    let mut debug_writer: HashMap<u64, Option<std::io::BufWriter<std::fs::File>>> = HashMap::new();
    let mut stream_total: Vec<usize> = Vec::new();

    // Consumer is the one consumer we expect to have (Which is updated once we have a connection)
    let mut consumer: u64 = 0;
    // We store if we are currently waiting for a request
    let mut wait_for_new_req = false; 

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(args.listen_to.parse().unwrap()).unwrap();

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    if !args.disable_pacing {
        match set_txtime_sockopt(&socket) {
            Ok(_) => {
                pacing = true;
                debug!("successfully set SO_TXTIME socket option");
            },
            Err(e) => debug!("setsockopt failed {:?}", e),
        };
    }

    info!("listening on {:}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = if args.disable_gso {
        false
    } else {
        detect_gso(&socket, max_datagram_size)
    };

    trace!("GSO detected: {}", enable_gso);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(&args.cert).unwrap();
    config.load_priv_key_from_pem_file(&args.key).unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);
    config.set_initial_congestion_window_packets(
        usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
    );

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    config.enable_pacing(pacing);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    // let mut pkt_count = 0;

    let mut continue_write = false;

    let local_addr = socket.local_addr().unwrap();
    
    let mut log_writer = match args.store_eval{
        Some(ref p) => {
            // Make BufWriter
            let path = format!("{}/server-tx.txt",p);
            let file = fs::OpenOptions::new().create(true).append(true).open(&path);
            match file{
                Ok(v) => Some(BufWriter::new(v)),
                Err(_) => None,
            }
        },
        None => None,
    };
    // Make header of log file
    match log_writer {
        Some(ref mut w) => {
            let text = format!("timestamp;link;connection-id;content-type;stream-id;has-header;has-body;was-dropped;urgency;incremental;body-bytes\n");
            w.write_all(text.as_bytes()).ok();
            w.flush().unwrap();
        },
        None => (),
    }

    let path = format!("./logs/forwarding.txt");
    let file = fs::OpenOptions::new().create(true).append(true).open(&path);
    let mut forwarding_writer =match file{
        Ok(v) => Some(BufWriter::new(v)),
        Err(_) => None,
    };
    // Make header of log file
    match forwarding_writer {
        Some(ref mut w) => {
            let text = format!("timestamp;producer-id;content-type;stream-id;producer-starvation;urgency;threshold;delivery_rate;\n");
            w.write_all(text.as_bytes()).ok();
            w.flush().unwrap();
        },
        None => (),
    }


    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            //false => clients.values().filter_map(|c| c.conn.timeout()).min(),
            false => Some(std::time::Duration::from_millis(100)),
        };

        // Blocks if there was nothing to read on the IPC channel
        // Checks for messages on the socket
        poll.poll(&mut events, timeout).unwrap();
        debug!("Poll didn't block");

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid) &&
                !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.no_retry {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http_conn: None,
                    client_id,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    app_proto_selected: false,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;
                
                // Safe cid of our client (hacky way to only use a single client without getting rid of the rest of the code)
                consumer = client_id;

                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&conn_id).unwrap(),
                };

                // Safe cid of our client (hacky way to only use a single client without getting rid of the rest of the code)
                if consumer != *cid {
                    consumer = *cid;
                }

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();

                #[allow(clippy::box_default)]
                if alpns::HTTP_09.contains(&app_proto) {
                    client.http_conn = Some(Box::<Http09Conn>::default());

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(&app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        conn_args.max_field_section_size,
                        conn_args.qpack_max_table_capacity,
                        conn_args.qpack_blocked_streams,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ) {
                        Ok(v) => Some(v),

                        Err(e) => {
                            trace!("{} {}", client.conn.trace_id(), e);
                            None
                        },
                    };

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();
            }

            if client.http_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http_conn.as_mut().unwrap();
                // let partial_responses = &mut client.partial_responses;
                let partial_requests = &mut client.partial_requests;

                if policy.is_empty(){
                    policy.push(Priority::new(0,false));
                }
                // A request arrived (and is processed now)
                // wait_for_new_req = false;

                // Don't fill partial_respones with anything

                // Stores one request in partial_requests per stream (0,4,8,...)
                // Possibly we don't need this because we only use it to count the number of open streams, right?
                // root and index are hardcoded because not needed in this scenario but I did not want 
                // to remove the possibility ot GET requests from the helper functions in common.rs
                if http_conn
                    .handle_requests(
                        conn,
                        partial_requests,
                        &mut lonly_headers,
                        "127.0.0.1:4433",
                        "index.html",
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }

                //Check if we have a stream to write on
                if partial_requests.len() > conn_map.len(){

                    //////////////////////////////////////////////////////////////////////////////////////////////
                    // Check if new stream_id - connection - mapping arrived                                    //
                    // This part is about registering a new producer with out variables                         //
                    //////////////////////////////////////////////////////////////////////////////////////////////
                    trace!("conn_map: {:?}, partial_requests: {:?}, lonly_headers: {:?}", conn_map.len(), partial_requests.len(),lonly_headers.len());
                    if !lonly_headers.is_empty() && wait_for_new_req{
                        // A request arrived (and is processed now)
                        wait_for_new_req = false;

                        for (&stream_id,response) in &mut lonly_headers{
                            let mut cid = None;
                            let mut path = None;
                            match &response.headers {
                                Some(headers) => {
                                    for hdr in headers{
                                        match hdr.name(){
                                            b"conn-id" => {
                                                cid = Some(std::str::from_utf8(hdr.value()).unwrap());
                                            },

                                            b":path" => {
                                                path = Some(std::str::from_utf8(hdr.value()).unwrap())
                                            },
                            
                                            _ => (),
                                        };
                                    }
                                    match cid {
                                        // If there is a connection id update the conn_map
                                        Some(c) => {
                                            policy.push(Priority::new(3,true));

                                            // Logic for storing data before relaying it
                                            // Let debug_writer for this string be Some if path was given and no error occured, else let it be None
                                            let writer = match args.store_tx{
                                                Some(ref p) => {
                                                    // Get filename from header
                                                    let file_name = match path {
                                                        Some(name) => {
                                                            let v: Vec<&str> = name.split("/").collect();
                                                            ["",v[v.len()-1]].join("/")
                                                        },
                                                        None => "/SomeData.txt".to_string(),
                                                    };
                                                    // Make BufWriter
                                                    let path = format!("{}{}",p, file_name);
                                                    let file = fs::OpenOptions::new().create(true).append(true).open(&path);
                                                    match file{
                                                        Ok(v) => Some(BufWriter::new(v)),
                                                        Err(_) => None,
                                                    }
                                                },
                                                None => None,
                                            };
                                            debug_writer.insert(stream_id,writer);

                                            // Count bytes written on this stream
                                            let i = usize::try_from(stream_id/4).unwrap();
                                            while stream_total.len() <= i{
                                                stream_total.push(0);
                                            }

                                            let header_with_features = match partial_header.get(c){
                                                Some(resp) => {
                                                    match resp.headers.clone() {
                                                        Some(headers) => headers,
                                                        None => {
                                                            error!("Got no features from new producer!");
                                                            Vec::new()
                                                        }
                                                    }
                                                },
                                                None => {
                                                    error!("Got no initial header!");
                                                    Vec::new()
                                                }
                                                
                                            };
                                            let (features, header) = parse_features_from_hdr(header_with_features);

                                            //Create new producer
                                            let prod = Producer {
                                                conn_id: c.to_string(),
                                                stream_id,
                                                features,
                                                feature_updated: true,
                                                priority: Priority::default(),
                                                times_sent: 0,
                                            };
                                            debug!("Add producer {:?} to producers", prod);
                                            producers.insert(c.to_string(),prod);

                                            // Update partial header to exclude the features
                                            match partial_header.get_mut(c){
                                                Some(resp) => {
                                                    resp.headers = Some(header)
                                                }
                                                None => (),
                                            }

                                            // Map rx-connection-id to tx-stream
                                            conn_map.insert(c.to_string(),stream_id)
                                        },
                                        None => None,
                                    };
                                },
                                None => (),
                            };
                        }
                        for (_,producer) in producers.clone() {
                            let stream_id = producer.stream_id;
                            lonly_headers.remove(&stream_id);
                        }
                    }
                    //////////////////////////////////////////////////////////////////////////////////////////////

                    if !wait_for_new_req {

                        // Handle writable streams.
                        for stream_id in conn.writable() {
                            // http_conn.handle_writable(conn, partial_responses, stream_id);
                            let partial_response = lonly_bodies.get(&stream_id);
                            match partial_response{
                                Some (response) =>{
                                    let resp = PartialResponse{
                                        headers: response.headers.clone(),
                                        priority: None,
                                        body: response.body.clone(),
                                        written: response.written.clone()
                                    };
                                    lonly_bodies.remove(&stream_id);
                                    match http_conn.get_h3_conn(){
                                        Some(h3_conn) => send_request_with_priority(h3_conn, conn, resp, stream_id, &mut lonly_bodies, &mut stream_total),
                                        None => error!("Not able to send with priority: No H3 Connection"),
                                    };
                                },
                                None => (),
                            }

                        }
                    

                        // Upon getting data from a new connection id, send headers on control stream
                        // On existing connection: Just forward to correct stream_id
                        match rx.recv(){
                            Ok((conn_id,mut response)) =>{
                                // Log incoming datum if needed
                                // match log_writer {
                                //     Some(ref mut w) => {  
                                //         let system_time = SystemTime::now();
                                //         let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
                                //         let text = match datetime {
                                //             // timestamp;link;connection-id;stream-id;has-header;has-body;urgency;incremental;body-bytes
                                //             Ok(t) => format!("{};channel;{};NaN;{};{};NaN;NaN;NaN;{}\n", t.as_nanos(), conn_id.clone(), response.headers.is_some(), !response.body.is_empty(), conn.stats().sent_bytes),
                                //             Err(_) => format!("NaN;channel;{};NaN;{};{};NaN;NaN;NaN;{}\n", conn_id.clone(), response.headers.is_some(), !response.body.is_empty(), conn.stats().sent_bytes),
                                //         };
                                //         w.write_all(text.as_bytes()).ok();
                                //         w.flush().unwrap();
                                //     },
                                //     None => (),
                                // }

                                //////////////////////////////////////////////////////////////////////////////////////////////
                                // If the producer is already known, get the priority of the producer                       //
                                // Else (If the producer is new), offer the data stream to the consumer (ask for stream id) //
                                //////////////////////////////////////////////////////////////////////////////////////////////
                                let mut producer_type = "".to_string();
                                
                                let (stream_id,prio) = match producers.get_mut(&conn_id){
                                    Some(producer) => {

                                        // Check if his is the first message since the inital header
                                        if response.headers.is_none(){
                                            response.headers = match partial_header.remove(&conn_id) {
                                                Some(v) => {
                                                    v.headers.clone()
                                                },
                                                None => None,
                                            };
                                        }

                                        // Actually get the  stream_id, and the priority
                                        get_prio_from_policy(&prioritization,producer, &feature_policy_list, &feature_weight_list)
                                    },
                                    None => {
                                        trace!("New producer arrived at TX component, producers is: {:?}", producers);
                                        warn!("Connection {} is new! Client needs to set up a new stream!", conn_id);
                                        conn_map.insert(conn_id.clone(),0);
                                        // Store old headers to use once the stream for the new producer is set up
                                        let old_header = PartialResponse{
                                            headers: response.headers.clone(),
                                            priority: None,
                                            body: Vec::new(),
                                            written: 0,
                                        };
                                        partial_header.insert(conn_id.clone(), old_header);
                                        // Mark that we are waiting for a request on a new stream from the consumer
                                        wait_for_new_req = true;

                                        // Make new header to get new stream from consumer
                                        // response.headers = Some(vec![
                                        //     quiche::h3::Header::new(b"conn-id",conn_id.as_bytes())
                                        // ]);

                                        response.headers = match response.headers {
                                            Some(mut header) => {
                                                header.push(quiche::h3::Header::new(b"conn-id",conn_id.as_bytes()));
                                                Some(header)
                                            },
                                            None => {
                                                let mut header = Vec::new();
                                                header.push(quiche::h3::Header::new(b"conn-id",conn_id.as_bytes()));
                                                Some(header)
                                            },
                                        };
                                        // Requests use the control channel which always has highest priority
                                        (0,Priority::new(0,false))
                                    },                     
                                };
                                response.priority = Some(prio.clone());
                                //////////////////////////////////////////////////////////////////////////////////////////////

                                // TODO: Add check on estimated bandwidth and priority. Only log and send as not-dropped if priority is high enough
                                //       There is conn.stats().cwnd to get the current congestion window of the connection

                                //////////////////////////////////////////////////////////////////////////////////////////////

                                // Get logging values of the datum that will be sent
                                let has_header = response.headers.is_some();
                                let has_body = !response.body.is_empty();
                                let resp_body = response.body.clone();
                                let u = prio.get_tuple().0;
                                let inc = prio.get_tuple().1;

                                //////////////////////////////////////////////////////////////////////////////////////////////
                                // Forward the datum or the request to the consumer, if the connection is new or            //
                                // if the producers priority is high enough                                                 //
                                //////////////////////////////////////////////////////////////////////////////////////////////
                                trace!("header: {:?}, body: {:?}", response.headers.clone(), response.body.clone());
                                let mut forward_decision = true;
                                if producers.get(&conn_id).is_some(){
                                    let mut producer = producers.get_mut(&conn_id).unwrap().clone();
                                    producer_type = producer.features.content_type.clone();
                                    trace!("Producer is: {:?}", producer);
                                    forward_decision = discard_body(conn, &mut producer, &producers, no_dropping, sending_rate);
                                    trace!("forward decision is: {}", forward_decision);
                                    producers.insert(conn_id.clone(),producer);
                                    trace!("Updated producers and response");
                                }
                                
                                match http_conn.get_h3_conn(){
                                    Some(h3_conn) => {
                                        // Ignore the forwarding decision
                                        if has_header {
                                            send_request_with_priority(h3_conn, conn, response, stream_id, &mut lonly_bodies, &mut stream_total);
                                        
                                        } else {
                                            // React to the forwarding decision
                                            if forward_decision {
                                                send_request_with_priority(h3_conn, conn, response, stream_id, &mut lonly_bodies, &mut stream_total);
                                            } else {
                                                let empty_response = PartialResponse{
                                                    headers: None,
                                                    priority: response.priority,
                                                    body: b"Dropped".to_vec(),
                                                    written: 0,
                                                };
                                                send_request_with_priority(h3_conn, conn, empty_response, stream_id, &mut lonly_bodies, &mut stream_total);
                                            }
                                        }

                                //////////////////////////////////////////////////////////////////////////////////////////////

                                        if stream_id!=0{
                                            // For evaluation purposes:
                                            // timestamp;link;connection-id;content-type;stream-id;has-header;has-body;was-dropped;urgency;incremental;body-bytes;
                                            match log_writer {
                                                Some(ref mut w) => {
                                                    let system_time = SystemTime::now();
                                                    let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
                                                    let i: usize = (stream_id/4).try_into().unwrap();
                                                    let text = match datetime {
                                                        Ok(t) => format!("{};connection;{};{};{};{};{};{};{};{};{}\n", t.as_nanos(), conn_id.clone(), producer_type, stream_id, has_header, has_body, !forward_decision, u, inc, stream_total[i]),
                                                        Err(_) => format!("NaN;connection;{};{};{};{};{};{};{};{};{}\n", conn_id.clone(),producer_type, stream_id, has_header, has_body, !forward_decision, u, inc,stream_total[i]),
                                                    };
                                                    w.write_all(text.as_bytes()).ok();
                                                    w.flush().unwrap();
                                                },
                                                None => (),
                                            }
                                            // For debugging purposes:
                                            // Try storing in between (if saveintermediate = true in our script)
                                            let mut temp_writer = None;
                                            let writer =  match debug_writer.get_mut(&stream_id){
                                                Some(v) => v,
                                                None => &mut temp_writer,
                                            };

                                            match writer {
                                                Some(rw) => {
                                                    trace!("Writing to file: {:?}",rw);
                                                    trace!("Response body length is: {}", resp_body.len());
                                                    rw.write_all(&resp_body).ok();
                                                },
                                                None => (),
                                            }
                                        }
                                    },
                                    None => error!("Not able to send with priority: No H3 Connection"),
                                };
                            },
                            Err(_) => warn!("Channel empty and sender quit!"),
                        };
                    }
                }
            }

            handle_path_events(client);
            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
                clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimun bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst =
                client.conn.send_quantum().min(client.max_send_burst) /
                    client.max_datagram_size *
                    client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) = match client
                    .conn
                    .send(&mut out[total_write..max_send_burst])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    continue_write = true;
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                break;
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            trace!("{} written {} bytes", client.conn.trace_id(), total_write);

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                for id in c.conn.source_ids() {
                    let id_owned = id.clone().into_owned();
                    clients_ids.remove(&id_owned);
                }
            }

            !c.conn.is_closed()
        });
    }
}
////////////////////////////////////////////// End of TX API //////////////////////////////////////////////


/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            },

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },
        }
    }
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsRawFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    // mio::net::UdpSocket doesn't implement AsFd (yet?).
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(sock.as_raw_fd()) };

    setsockopt(&fd, TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;

    Err(Error::new(
        ErrorKind::Other,
        "Not supported on this platform",
    ))
}

////////////////////////////////////// Helper functions for forwarding requests ///////////////////////////

// Replaces handle_writable() in forwarding scenario
fn send_request_with_priority(
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection, 
    partial_response: PartialResponse,
    stream_id: u64,
    lonly_bodies: &mut HashMap<u64,PartialResponse>,
    stream_total: &mut Vec<usize>,
){
    debug!("Sending request to C on stream {}", stream_id);

    let i: usize = (stream_id/4).try_into().unwrap();

    let resp = partial_response;
    let fin: bool = if resp.written > 0 {
        info!("Fin bit is: {}", true);
        true
    }else{
        false
    };

    // Hopefully there are no headers of kind: Some(Vec::new())
    // TO change priority without sending a header call: conn.stream_priority
    if resp.body.len() > 0 {
         // Stream should already exists at this point in time
        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
            match h3_conn.send_response_with_priority(
                conn, stream_id, headers, priority, false,
            ) {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    lonly_bodies.insert(stream_id, resp);
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed while sending headers with priority {:?}", conn.trace_id(), e);
                    return;
                },
            }
        }
        let mut written = 0;
        let len = resp.body.len();
        while written < len{
            match h3_conn.send_body(conn, stream_id, &resp.body[..],fin){
                Ok(v) => {
                    written = written + v;
                    stream_total[i] = stream_total[i] + v;
                },
                Err(quiche::h3::Error::StreamBlocked) => {
                    match lonly_bodies.get(&stream_id){
                        Some(response) =>{
                            // Append new body behind already stored body
                            let mut body = Vec::new();
                            body.extend(response.body.clone());
                            body.extend_from_slice(&resp.body[written..]);
                            let resp = PartialResponse {
                                 headers: response.headers.clone(), 
                                 priority: resp.priority, 
                                 body, 
                                 written: resp.written, 
                                };
                            lonly_bodies.insert(stream_id, resp);
                        },
                        None => {
                            let resp = PartialResponse{
                                headers: None,
                                priority: None,
                                body:resp.body[written..].to_vec(),
                                written: resp.written,
                            };
                            lonly_bodies.insert(stream_id, resp);
                        }
                    }

                    if written < len{
                        warn!("written smaller than body due to done {}", stream_id);
                    }
                    return;
                },
                Err(quiche::h3::Error::Done) => {
                    match lonly_bodies.get(&stream_id){
                        Some(response) =>{
                            // Append new body behind already stored body
                            let mut body = Vec::new();
                            body.extend(response.body.clone());
                            body.extend_from_slice(&resp.body[written..]);
                            let resp = PartialResponse {
                                 headers: response.headers.clone(), 
                                 priority: resp.priority, 
                                 body, 
                                 written: resp.written, 
                                };
                            lonly_bodies.insert(stream_id, resp);
                        },
                        None => {
                            let resp = PartialResponse{
                                headers: None,
                                priority: None,
                                body:resp.body[written..].to_vec(),
                                written: resp.written,
                            };
                            lonly_bodies.insert(stream_id, resp);
                        }
                    }

                    if written < len{
                        warn!("written smaller than body due to done {}", stream_id);
                    }
                    return;
                },
                Err(e) => {
                    error!("stream send failed while sending some body {:?} on stream {} with priority {:?}",resp.body,stream_id,e);
                    debug!("Response headers: {:?}, Response body: {:?}", resp.headers, resp.body);
                    return;
                },
            }
        }
    if written < len{
        warn!("written smaller than body without reason {}", stream_id);
    }
    } else {
        // Stream should already exists at this point in time
        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
            match h3_conn.send_response_with_priority(
                conn, stream_id, headers, priority, fin,
            ) {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed while sending headers with priority {:?}", conn.trace_id(), e);
                    return;
                },
            }
        }
    }

    debug!("Priority for partial response on stream {} is {:?}",stream_id,resp.priority);
    if resp.written > 0{
        info!("Stream {} sent {} bytes", stream_id, stream_total[i]);
    }
}

// Replaces handle_requests() in forwarding scenario
fn accept_request(
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection, 
    buf: &mut [u8],
    tx: &mpsc::Sender<(String,PartialResponse)>,
    store_rx: &Option<String>,
    debug_writer: &mut HashMap<String,Option<std::io::BufWriter<std::fs::File>>>, 
    log_writer: &mut Option<BufWriter<std::fs::File>>,
    conns_total: &mut HashMap<String,usize>,
) -> u64{
    // Store highest stream id used on this connection
    let mut highest_stream_id: u64 = 0;
    // Process HTTP stream-related events.
    loop {
        match h3_conn.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, has_body })) => {
                let system_time = SystemTime::now();
                let body_str = { if has_body {
                    "a"
                }
                else {
                    "no"
                }};
                info!(
                    "{} got request {:?} with {} body on stream id {}",
                    conn.trace_id(),
                    hdrs_to_strings(&list),
                    body_str,
                    stream_id
                );

                // Store this to use in go_away case
                highest_stream_id =
                        std::cmp::max(highest_stream_id, stream_id);

                // Parse part of the header to be used for logging and storing purposes
                let mut file_name = None;
                let mut conn_id = None;
                for hdr in &list{
                    match hdr.name(){
                        b":path" => file_name = Some(std::str::from_utf8(hdr.value()).unwrap()),
                        b"conn-id" => conn_id = Some(std::str::from_utf8(hdr.value()).unwrap()),
                        _ => (),
                    }
                }
                
                // Log header with connection-id from A if possible
                match conn_id {
                    Some(cid) => {
                        // Log header
                        match log_writer {
                            Some(w) => {
                                let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
                                let text = match datetime {
                                    Ok(t) => format!("{};header;{};{};0\n", t.as_nanos(), conn.trace_id().to_string(),cid.to_string()),
                                    Err(_) => format!("NaN;header;{};{};0\n", conn.trace_id().to_string(), cid.to_string()),
                                };
                                w.write_all(text.as_bytes()).ok();
                                w.flush().unwrap();
                            },
                            None => (),
                        }
                    },
                    None => {
                        // Log header
                        match log_writer {
                            Some(w) => {
                                let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
                                let text = match datetime {
                                    Ok(t) => format!("{};header;{};NaN;0\n", t.as_nanos(), conn.trace_id().to_string()),
                                    Err(_) => format!("NaN;header;{};NaN;0\n", conn.trace_id().to_string()),
                                };
                                w.write_all(text.as_bytes()).ok();
                                w.flush().unwrap();
                            },
                            None => (),
                        }
                    },
                }

                // Try to store data if storing path is given
                let h3_writer = match store_rx{
                    Some(p) => {
                        let file_name = match file_name {
                            Some(name) => {
                                let v: Vec<&str> = name.split("/").collect();
                                ["",v[v.len()-1]].join("/")
                            },
                            None => "/SomeData.txt".to_string(),
                        };
                        let path = format!("{}{}", p, file_name);
                        let file = fs::OpenOptions::new().create(true).append(true).open(&path);
                        match file{
                            Ok(v) => Some(BufWriter::new(v)),
                            Err(_) => None,
                        }
                    },
                    None => None
                };
                debug_writer.insert(conn.trace_id().to_string(),h3_writer);
                conns_total.insert(conn.trace_id().to_string(),0);

                // Hacky way to pass fin bit
                let fin_bit: usize = usize::try_from(!has_body).unwrap();
                
                // Make partial response for headers
                let partial_header = PartialResponse {
                    headers: Some(list),
                    priority: None,
                    body: Vec::new(),
                    written: fin_bit,
                };

                // Pass connection trace id and partial header
                let conn_id = format!("{}",conn.trace_id());
                debug!("Transmitting to channel");
                match tx.send((conn_id.clone(),partial_header)){
                    Ok(_) => (),
                    Err(e) => {
                        error!("Error sending partial response, {:?}", e);
                        panic!();
                    },
                };
                // thread::sleep(Duration::from_millis(1));
                
            },

            Ok((stream_id, quiche::h3::Event::Data)) => {
                trace!(
                    "{} got data on stream id {}",
                    conn.trace_id(),
                    stream_id
                );
                
                // handle the request body
                while let Ok(read) =
                    h3_conn.recv_body(conn, stream_id, buf)
                {
                    debug!(
                        "got {} bytes of body data on stream {}",
                        read, stream_id
                    );

                    // Hacky way to pass fin bit
                    let fin_bit: usize = if conn.stream_finished(stream_id){
                        1
                    } else {
                        0
                    };

                    // Headers and priority are already sent at this point
                    let mut body = Vec::new();
                    body.extend_from_slice(&buf[..read]);

                    // Try to store data
                    let writer = debug_writer.get_mut(&conn.trace_id().to_string()).unwrap();
                    match writer {
                        Some(rw) => {
                            trace!("Writing to file: {:?}",rw);
                            rw.write_all(&body).ok();
                        },
                        None => (),
                    }

                    // Log body
                    match log_writer {
                        Some(w) => {
                            let system_time = SystemTime::now();
                            let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
                            let old_transmitted = conns_total.get(&conn.trace_id().to_string()).unwrap();
                            let now_transmitted = old_transmitted + body.len();
                            conns_total.insert(conn.trace_id().to_string(), now_transmitted);
                            let text = match datetime {
                                Ok(t) => format!("{};body;{};NaN;{}\n", t.as_nanos(), conn.trace_id().to_string(), now_transmitted),
                                Err(_) => format!("NaN;body;{};NaN;{}\n", conn.trace_id().to_string(), now_transmitted),
                            };
                            w.write_all(text.as_bytes()).ok();
                            w.flush().unwrap();
                        },
                        None => (),
                    }

                    let partial_body = PartialResponse {
                        headers: None,
                        priority: None,
                        body,
                        written: fin_bit,
                    };

                    // Pass connection trace id and partial body
                    let conn_id = format!("{}",conn.trace_id());
                    debug!("Transmitting to channel");
                    match tx.send((conn_id.clone(),partial_body)){
                        Ok(_) => (),
                        Err(e) => error!("Error sending partial response, {:?}", e),
                    };

                    // In case the fin bit was set on this stream id, reply to the sender and stop forwarding
                    if fin_bit>0 && conn.stream_finished(stream_id){
                        // Store last bytes of stored data
                        let res = match writer {
                            Some(rw) => rw.flush(),
                            None => Ok(()),
                        };
                        match res {
                            Ok(_) => (),
                            Err(_) => warn!("Flushing writer returned an error!"),
                        }
                        let body = Vec::new();
                        let headers = vec![
                            quiche::h3::Header::new(b":status", b"202"),
                            quiche::h3::Header::new(b"server", b"quiche"),
                            quiche::h3::Header::new(
                                b"content-length",
                                body.len().to_string().as_bytes(),
                            ),
                        ];
                        let resp = PartialResponse{
                            headers: Some(headers),
                            body,
                            priority: Some(Priority::new(3,true)),
                            written: 0,
                        };
                        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
                            match h3_conn.send_response_with_priority(
                                conn, stream_id, headers, priority, false,
                            ) {
                                Ok(_) => (),
                
                                Err(quiche::h3::Error::StreamBlocked) => (),
                
                                Err(e) => error!("{} stream send failed while sending headers with priority {:?} to A", conn.trace_id(), e),
                            }
                        }
                        
                        let body = &resp.body[resp.written..];
                
                        match h3_conn.send_body(conn, stream_id, body, true) {
                            Ok(_) => (),
                
                            Err(quiche::h3::Error::Done) => (),
                
                            Err(e) => error!("{} stream send failed while writing a body to A", e),
                        };

                    }
                    // thread::sleep(Duration::from_millis(1));

                }
            },

            Ok((_, quiche::h3::Event::Finished)) => (),

            Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

            Ok((_, quiche::h3::Event::PriorityUpdate)) => (),

            Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                trace!(
                    "{} got GOAWAY with ID {} ",
                    conn.trace_id(),
                    goaway_id
                );
                // Add .ok() because of unused Result (TODO: DO something better)
                h3_conn
                    .send_goaway(conn, highest_stream_id).ok();
            },

            Err(quiche::h3::Error::Done) => {
                return highest_stream_id;
            },

            Err(e) => {
                error!("{} HTTP/3 error {:?}", conn.trace_id(), e);
            },
        }
    }
    // Maybe later also handle datagrams
}

#[derive(Clone, Debug)]
struct Producer {
    conn_id: String,
    stream_id: u64,
    features: Features,
    feature_updated: bool,
    priority: Priority,
    times_sent: u8,
}

#[derive(Clone, Debug)]
struct Features {
    content_type: String,
    device_type: String,
    incremental: bool,
    sending_rate: String,
    starvation_rate: f32,
    starving: u8,
}

fn parse_features_from_hdr(header: Vec<quiche::h3::Header>) -> (Features, Vec<quiche::h3::Header>) {

    let mut new_header: Vec<quiche::h3::Header> = Vec::new();

    // Get the values of the header fields
    let mut maybe_content = None;
    let mut maybe_device = None;
    let mut maybe_inc = None;
    let mut maybe_sending = None;
    let mut maybe_starvation = None;

    for hdr in &header{
        match hdr.name(){
            b"content-type" => maybe_content = Some(std::str::from_utf8(hdr.value()).unwrap()),
            b"device-type" => maybe_device = Some(std::str::from_utf8(hdr.value()).unwrap()),
            b"incremental" => maybe_inc = Some(std::str::from_utf8(hdr.value()).unwrap()),
            b"sending-rate" => maybe_sending = Some(std::str::from_utf8(hdr.value()).unwrap()),
            b"starvation-rate" => maybe_starvation = Some(std::str::from_utf8(hdr.value()).unwrap()),
            _ => {
                let header_field = hdr;
                new_header.push(header_field.clone())
            },
        }
        header.iter().position(|h| h == hdr);
    }

    // Parse the Option<String> values to actually usable values
    let content_type = match maybe_content {
        Some(str) => str.to_string(),
        None => "default".to_string()
    };
    let device_type = match maybe_device {
        Some(str) => str.to_string(),
        None => "default".to_string()
    };
    let incremental: bool = match maybe_inc {
        Some(str) => {
            if str.parse::<bool>().is_err() {
                false
            } else {
                str.parse().unwrap()
            }
        },
        None => false
    };
    let sending_rate = match maybe_sending {
        Some(str) => str.to_string(),
        None => "default".to_string()
    };
    let starvation_rate: f32 = match maybe_starvation {
        Some(str) => {
            if str.parse::<f32>().is_err() {
                0.0
            } else {
                str.parse().unwrap()
            }
        },
        None => 0.0
    };

    // Build Features from parsed values
    let features = Features {
        content_type,
        device_type,
        incremental,
        sending_rate,
        starvation_rate,
        starving: 0,
    };

    return (features, new_header);
}
///////////////////////////////////////   Forwarding-Decision Module   //////////////////////////////////////////////////

fn discard_body(conn: &mut quiche::Connection, producer: &mut Producer, producers: &HashMap<String, Producer>, reliably: bool, maybe_rate: Option<u64>) -> bool {
    // Always forward if reliably is true
    if reliably {
        return true
    }
    // If we defined a delivery rate use that one instead of the delivery_rate estimation from PathStats
    let delivery_rate = match maybe_rate{
        Some(rate) => rate,
        None => avg_delivery_rate(conn)*8,
    };

    let (threshold, not_used_bandwidth) = make_threshold(producers, delivery_rate);
    info!("Made threshold: {}", threshold);

    // Yes this path is hardcoded, but it would be nice to also replace this by some variable path
    let path = format!("./logs/forwarding.txt");
    let file = fs::OpenOptions::new().create(true).append(true).open(&path);
    let mut log_writer =match file{
        Ok(v) => Some(BufWriter::new(v)),
        Err(_) => None,
    };
    // Log forwarding decision: timestamp;producer-id;stream-id;producer-starvation;urgency;threshold;delivery_rate;
    match log_writer {
        Some(ref mut w) => {
            let system_time = SystemTime::now();
            let datetime = system_time.duration_since(SystemTime::UNIX_EPOCH);
            let text = match datetime {
                Ok(t) => format!("{};{};{};{};{};{};{};{}\n", t.as_nanos(),producer.conn_id, producer.features.content_type, producer.stream_id, producer.features.starving,producer.priority.get_tuple().0, threshold, delivery_rate),
                Err(_) => format!("NaN;{};{};{};{};{};{};{}\n",producer.conn_id, producer.features.content_type, producer.stream_id, producer.features.starving,producer.priority.get_tuple().0, threshold, delivery_rate),
            };
            w.write_all(text.as_bytes()).ok();
            w.flush().unwrap();
        },
        None => (),
    }

    if producer.priority.get_tuple().0 <= threshold {
        // Producer is in priority range
        return true;
    } else {
        // Producer is not in priority range and needs to take the leftovers
        let cid = get_next_important_producer_id(producers,threshold);
        

        let out_of_twenty = producer.features.starving + producer.times_sent;
        if cid == producer.conn_id{
            // If our producer is the next important producer after the threshold
            // Then care about him

            // Get the percentage of his sending_rate that is left over on the connection
            let producer_rate = rate_to_bits(producer.features.sending_rate.clone());
            let float_nominator =  (not_used_bandwidth as f32)*(20.0/(producer_rate as f32));
            let nominator: u64 = float_nominator.round() as u64;
            debug!("Start comparing starvation: {}, nominator: {}, unused bandwith: {}, producer_rate: {}", producer.features.starving, nominator, not_used_bandwidth, producer_rate);
            if (producer.features.starving as u64) <= nominator {
                if 20 > out_of_twenty{
                    producer.times_sent = producer.times_sent + 1;
                } else {
                    producer.times_sent = 0;
                    producer.features.starving = 0;
                    producer.feature_updated = true;
                }
                return true;
            } else {
                if 20 > out_of_twenty {
                    producer.features.starving = producer.features.starving + 1;
                    producer.feature_updated = true;
                } else {
                    producer.times_sent = 0;
                    producer.features.starving = 0;
                    producer.feature_updated = true;
                }
                return false;
            }
        } else {
            debug!("This producer is unimportant");
            if 20 > out_of_twenty {
                producer.features.starving = producer.features.starving + 1;
                producer.feature_updated = true;
            } else {
                producer.times_sent = 0;
                producer.features.starving = 0;
                producer.feature_updated = true;
            }
            return false;
        }
    }
}

fn get_next_important_producer_id(producers: &HashMap<String,Producer>, threshold: u8) -> String{
    let mut conn_id = String::new();
    let mut important_urgency:u8 = 7;
    for (_,producer) in producers{
        let producer_urgency = producer.priority.get_tuple().0;
        if producer_urgency < important_urgency && threshold < producer_urgency {
            conn_id = producer.conn_id.clone();
            important_urgency = producer_urgency;
        }
    }
    return conn_id;
}

fn make_threshold(producers: &HashMap<String, Producer>, delivery_rate_bits: u64) -> (u8, u64) {
    let mut delivery_rate_per_urgency = [0,0,0,0,0,0,0,0];
    for (_,producer) in producers {
        let u = producer.priority.get_tuple().0;
        let rate = producer.features.sending_rate.clone();
        let bitrate = rate_to_bits(rate);
        delivery_rate_per_urgency[u as usize] = delivery_rate_per_urgency[u as usize] + bitrate;
    }
    trace!("Delivery-rate-bits: {:?}", delivery_rate_bits);
    
    let mut current_rate = 0;
    let mut u: u8 = 0;
    let mut threshold:u8 = 0;

    'thres: loop{
        if u < 8 {
            if (current_rate + delivery_rate_per_urgency[u as usize]) < delivery_rate_bits {
                current_rate = current_rate + delivery_rate_per_urgency[u as usize];
                threshold = u;
                u = u+1;
            } else {
                break 'thres;
            }
        } else {
            break 'thres;
        }
    }

    let not_used_rate = delivery_rate_bits - current_rate;
    return (threshold, not_used_rate);
}

fn rate_to_bits(rate:String) -> u64{
    let bitrate: u64 = match rate {
        s if s.contains("tbit") => s[0..(s.len()-4)].parse::<u64>().unwrap()*1000000000000,
        s if s.contains("gbit") => s[0..(s.len()-4)].parse::<u64>().unwrap()*1000000000,
        s if s.contains("mbit") => s[0..(s.len()-4)].parse::<u64>().unwrap()*1000000,
        s if s.contains("kbit") => s[0..(s.len()-4)].parse::<u64>().unwrap()*1000,
        s if s.contains("bit") => s[0..(s.len()-3)].parse::<u64>().unwrap(),
        _ => 1
    };
    return bitrate;
}

fn avg_delivery_rate(conn: &mut quiche::Connection) -> u64 {
    // Get average delivery_rate over all existing paths for this connection
    // Collect the path statistics into a vector
    let path_stats: Vec<PathStats> = conn.path_stats().collect();

    // Calculate the average delivery_rate
    let total_delivery_rate: u64 = path_stats.iter().map(|ps| ps.delivery_rate).sum();
    let average_delivery_rate = if !path_stats.is_empty() {
        total_delivery_rate as f64 / path_stats.len() as f64
    } else {
        0.0
    };
    let rate = average_delivery_rate.round() as u64;
    return rate;
}

fn _max_delivery_rate(conn: &mut quiche::Connection) -> u64 {
    // Get average delivery_rate over all existing paths for this connection
    // Collect the path statistics into a vector
    let path_stats: Vec<PathStats> = conn.path_stats().collect();

    // Calculate the maximl delivery_rate
    let total_delivery_rate = path_stats.iter().map(|ps| ps.delivery_rate).max();
    let delivery_rate = match total_delivery_rate {
        Some(rate) => rate,
        None => 0,
    };
    return delivery_rate;
}

/////////////////////////////////////////   Prioritizaion Module   /////////////////////////////////////////////////////

/// This is the prioritization module of our implementation
/// This function uses some policies, the current producer, and a prioritization mode to determine the current priority for this producer
fn get_prio_from_policy(
    prioritization: &str,
    producer: &mut Producer, 
    feature_policy_list: &HashMap<String,HashMap<String,u8>>, 
    feature_weight_list: &HashMap<String,u8>
) -> (u64,Priority){

    // Features did not change since the last time the priority was calculated
    if !producer.feature_updated {
        return (producer.stream_id, producer.priority.clone());
    } 
    // Fetures did change => Recalulcate priority from current features
    else {
        let features = producer.features.clone();
        let cut_sending_rate = match features.sending_rate {
            s if s.contains("tbit") => "tbit".to_string(),
            s if s.contains("gbit") => "gbit".to_string(),
            s if s.contains("mbit") => "mbit".to_string(),
            s if s.contains("kbit") => "kbit".to_string(),
            s if s.contains("bit") => "bit".to_string(),
            _ => "default".to_string()
        };
        let urgency = match prioritization {
            "static Content-type" => 
                get_feature_value_from_policies(feature_policy_list,
                    "Content-type".to_string(), features.content_type),

            "static Device-type" => 
                get_feature_value_from_policies(feature_policy_list,
                    "Device-type".to_string(), features.device_type),

            "static sending-rate" => 
                get_feature_value_from_policies(feature_policy_list,
                    "Sending-rate".to_string(), cut_sending_rate),

            "dynamic weighted" => {
                let device_type_value = get_feature_value_from_policies(feature_policy_list,
                    "Device-type".to_string(), features.device_type);
                let device_type_weight = get_weight(feature_weight_list, "Device-type".to_string());
                let content_type_value = get_feature_value_from_policies(feature_policy_list,
                    "Content-type".to_string(), features.content_type);
                let content_type_weight = get_weight(feature_weight_list, "Content-type".to_string());
                let sending_rate_value = get_feature_value_from_policies(feature_policy_list,
                    "Sending-rate".to_string(), cut_sending_rate);
                let sending_rate_weight = get_weight(feature_weight_list, "Sending-rate".to_string());
                let starvation_value = get_dynamic_feature_value(features.starvation_rate, features.starving);
                let starvation_weight = get_weight(feature_weight_list, "Startvation".to_string());
                // Calculate weighted average
                let nominator = (device_type_weight*device_type_value)+
                    (content_type_weight*content_type_value)+
                    (sending_rate_weight*sending_rate_value)+
                    (starvation_weight*starvation_value);
                let denominator = device_type_weight+
                    content_type_weight+
                    sending_rate_weight+
                    starvation_weight;
                // Use the formula for the weighted average (0.0 <= float_urgency <= 7.0)
                let float_urgency = (nominator as f32)/(denominator as f32);
                // Convert float to int by rounding
                float_urgency.round() as u8
            },
            _ => unreachable!()
        };
        // Build the priority and update the producer
        let priority = Priority::new(urgency, features.incremental);
        producer.priority = priority.clone();
        producer.feature_updated = false;

        return (producer.stream_id, priority);
    }
}

fn import_policy_from_json(path:&str) -> HashMap<String,u8> {
    let mut content = String::new();
    match std::fs::File::open(path){
        Ok(mut f) => {
            if f.read_to_string(&mut content).is_err() {
                panic!("Panic! Because of an error while reading json to string");
            }
        },
        Err(e) => panic!("Panic! Because of {}", e)
    };
    let map: HashMap<String, u8> = match serde_json::from_str(&content) {
        Ok(map) => map,
        Err(_) => HashMap::new()
    };
    return map;  
}

/// Get the urgency based on a feature <feature_name> and its value <feature_value>,
/// In case of any errors, return urgency = 7 (least important)
fn get_feature_value_from_policies(feature_policy_list: &HashMap<String,HashMap<String,u8>>, feature_name: String, feature_value: String) -> u8 {
    let feature_policy = feature_policy_list.get(&feature_name);
    return match feature_policy {
        Some(map) => {
            let maybe_urgent = map.get(&feature_value);
            debug!("urgency: {:?}", maybe_urgent);
            match maybe_urgent {
                Some(&urgency) => urgency,
                None => 7
            }
        },
        None => 7
    }
}

fn get_dynamic_feature_value(starvation_rate:f32,starving:u8) -> u8 {
    // Convert float to integer. Usually we expect floats starting between 0.0 and 1.0 (with 5% accuracy)
    let starvation = (starvation_rate*20.0).round() as i32;
    // starvation \in [0,20] and starving \in [0,20], thus we expect starvation_diff \in [0,40]
    let starvation_sum = starvation+(starving as i32);
    let urgency = match starvation_sum {
        0..=2 => 7,
        3..=5 => 6,
        6..=8 => 5,
        9..=11 => 4,
        12..=14 => 3,
        15..=17 => 2,
        18..=20 => 1,
        // unexpected values and very high values
        _ => 0,
    };
    return urgency;
}

fn get_weight(feature_weight_list: &HashMap<String,u8>, feature_name: String) -> u8 {
    let maybe_urgent = feature_weight_list.get(&feature_name);
    let urgency = match maybe_urgent{
        Some(&u) => u,
        None => 7
    };
    return urgency;
}