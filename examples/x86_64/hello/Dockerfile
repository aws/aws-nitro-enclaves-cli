# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM busybox

ENV HELLO="Hello from the enclave side!"
COPY hello.sh /bin/hello.sh

CMD ["/bin/hello.sh"]
