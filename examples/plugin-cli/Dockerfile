# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This docker container will invoke a vault client which will initialize the
# require vault transit backend for the example
FROM vault:1.10.0
COPY scripts/run.sh ./
ENTRYPOINT ["sh","./run.sh"]
