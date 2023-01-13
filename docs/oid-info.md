# Sigstore OID information

## Description

Sigstore maintains its own Private Enterprise Number (57264) with the Internet
Assigned Numbers Authority to help identify and organize additional metadata in
code signing certificates issued by Fulcio instances. This document aims to
provide a simple directory of values in use with an explanation of their
meaning.

## Directory

Note that all values begin from the root OID 1.3.6.1.4.1.57264 [registered by
Sigstore][http://oid-info.com/get/1.3.6.1.4.1.57264].

When adding additional OIDs under the root, please update the above link with
the child OID.

| OID                 | Name                | Details                                                       |
| ------------------- | ------------------- | ------------------------------------------------------------- |
| 1.3.6.1.4.1.57264.1 | Fulcio              | https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md |
| 1.3.6.1.4.1.57264.2 | Timestamp Authority | https://github.com/sigstore/timestamp-authority               |
| 1.3.6.1.4.1.57264.3 | Rekor               | https://github.com/sigstore/rekor                             |
