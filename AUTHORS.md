# Authors and credits

**Queen_Glasser (@glasses666)** directs and maintains this DBY-W09 research,
owns the tested device, performs its physical recovery and acceptance steps,
and maintains the public result and evidence summaries.

Original repository: <https://github.com/glasses666/dby-w09-boot-research>.
Use [CITATION.cff](CITATION.cff) and identify the exact release or commit when citing it.

## Tools and upstream work

- AOSP and Google's ARM64 GSI supply Android userspace and upstream implementation references.
- Huawei/Qualcomm firmware on the owner's device supplies the retained hardware integration;
  those components are not claimed as this project's work.
- [REA / Reverse Engineer Anything](https://github.com/morluto/rea) and Ghidra assisted
  native-binary analysis and evidence review during staged boot investigations.
- Codex and ChatGPT assisted analysis, code, experiment design and documentation; real
  device operations and maintainer acceptance remain part of the evidence.
- APatch/KernelPatch provide the existing root environment. LiteGApps and its upstream
  components supply the optional Google layer; FlClash supplies the optional VPN client.

Tool credit does not imply sponsorship, endorsement or coauthorship by those projects.
Individual upstream notices continue to apply.
