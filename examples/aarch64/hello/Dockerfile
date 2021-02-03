# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM arm64v8/busybox

ENV HELLO="Hello from the enclave side!"
COPY hello.sh /bin/hello.sh

CMD ["/bin/hello.sh"]
