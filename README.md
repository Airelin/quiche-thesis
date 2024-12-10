This Thesis
----------------

### Abstract

In the Internet of Things (IoT) and more specifically in Industry 4.0 settings it has become common for systems to act far away from their monitoring devices. Thus, these systems need to send the produced data via the internet and shared links to their consumers, the monitoring units. For example, people monitor their smart home using their smartphone from everywhere, and farmers monitor their plants and autonomous systems from their office. These scenarios come with multiple challenges which are caused by a bottleneck between the producers and the consumer. While the producers are generating a huge amount of data, only part of them can be sent over the link to the consumer without high delays due to congestion. Thus, we propose to utilize resource prioritization on QUIC streams via HTTP/3 in order to optimize the communication between the producers and the consumer. Therefore, we introduce a relay server into the system which is close to the producers and prioritizes the data based on the current producer features before it forwards them to the consumer. Additionally, the relay server decides which data to forward based on the assigned priority and the current delivery rate estimation to avoid congesting the link to the consumer. We build a system to simulate the context to evaluate different prioritization algorithms in this scenario. We find that the system performs best with different configurations for different scenarios. Additionally, we see a huge impact on our system's performance arising from the choice of the congestion control algorithm.

-------------

### Repositories

We use multiple repositories to structure our code:
 - Quiche-Thesis
 - Quiche-Containers
 - Quiche-Eval

The **Quiche-Thesis** repository holds the code for our three applications. The start files of the applications are called 'quiche-server.rs', 'quiche-client.rs', and 'quiche-data.rs'.   
The **Quiche-Containers** repository holds archives which can be loaded as docker images. We provide two images per application. One image is the recommended implementation with the partial forwarding algorithm, the implementation in the other image does not include the partial forwarding algorithm.  
The **Quiche-Eval** repository includes the data we collected during our testing and experiments.

-------------

### Directory structure

We recommend the following directory structure:
 - Implementation
    - quiche-thesis
    - quiche-containers
    - quiche-eval

-------------

### Run the applications

You can build the applications' docker images from the codebase by running `./Build.sh` in the `quiche-thesis` directory. Then you can navigate to the `quiche-containers` directory and run any of the running scripts. We used the `exp3-prod.sh` to run three producers, one relay server, and one client. You can also run the `run3-prod.sh` which runs the `exp3-prod.sh` multiple times with different parameters.

----------------

![quiche](quiche.svg)

[quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
specified by the [IETF]. It provides a low level API for processing QUIC packets
and handling connection state. The application is responsible for providing I/O
(e.g. sockets handling) as well as an event loop with support for timers.

For more information on how quiche came about and some insights into its design
you can read a [post] on Cloudflare's blog that goes into some more detail.

[quiche]: https://docs.quic.tech/quiche/
[ietf]: https://quicwg.org/
[post]: https://blog.cloudflare.com/enjoy-a-slice-of-quic-and-rust/

Copyright
---------

Copyright (C) 2018-2019, Cloudflare, Inc.

See [COPYING] for the license.

[COPYING]: https://github.com/cloudflare/quiche/tree/master/COPYING
