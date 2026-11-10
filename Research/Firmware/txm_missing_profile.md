# Development CMS signatures with no TXM profile association

`txm-exp-missing_profile` is an opt-in research compatibility patch for the
combination of `kernel-boot-amfi_trustcache` and `txm-cfw-executable_remap`.
Both existing patches stay enabled. The standard preset leaves the new patch
off; the experimental preset includes it. Applicability is limited to cloudOS
26.4, whose signature layout and error path were inspected. An explicit allow
cannot widen that gate. No live VM has received this change yet.

This is a waiver of **missing provisioning-profile authorization**, not a
repair of profile registration. Native type 4 remains type 4. Non-null profile
checks, CMS classification, earlier finalizer checks, and executable remapping
checks retain their existing instructions.

## Reproduction

The affected guest uses cloudOS 26.4 and iOS 26.6.2. Launching an App whose
main executable retains its Apple Development CMS signature failed with
`NSPOSIXErrorDomain 85` and:

```text
TXM [Error]: CodeSignature: selector: 24 | 0xA6 | 0x12 | 1
```

The embedded profile was present, and misagent returned its matching UUID in
the failure window. That does not prove association with the TXM signature
object. Guest logs do not name the rejected Mach-O. The main executable and
AMFI fast path are a strongly supported attribution, not a live observation
of that object's type and profile pointer.

## Binary evidence and conflict

The original images were extracted from the locally cached cloudOS 26.4 IPSW.
Addresses below document this one image; production matching uses Capstone
operands and control flow, not those addresses.

| Object | Identity |
| --- | --- |
| TXM | `TrustedExecutionMonitor_Guarded-187.100.3` |
| TXM UUID | `B5296327-F14E-3430-9341-F452A4C9B571` |
| TXM SHA-256 | `819861b6b534b6dc53287b010e822b9d93633d07a29b6e5b968c076929ebfbc1` |
| Kernel collection SHA-256 | `86895a2eebeb7fcfb68bcd60f2d7e685687faea07ee31166fb58c872b38e0d92` |
| Embedded kernel UUID | `784F88D3-2AF5-3D4A-AB00-365607646E44` |
| AMFI UUID | `BAC1A875-32B3-3631-820E-791F9AD68B4E` |

The AMFI patch makes `AMFIIsCDHashInTrustCache` always return 1, also writing
metadata 1. In this kernel, the patched function is at
`0xfffffe0007de0294`. Its caller at `0xfffffe0007de7b80` reports a hit to the
vnode checker. The branch at `0xfffffe0007de9d80` enters normal CMS validation
only on a miss. The hit path bypasses the profile-submission call at
`0xfffffe0007deaf58`; the latter eventually calls `csblob_register_profile`
at `0xfffffe00092365c8`, then TXM profile association via selector 20.
XNU's `bsd/kern/ubc_subr.c` documents the same order: AMFI associates the
profile before the independent monitor validation.

The remap patch restores genuine TXM cache queries and keeps native CMS
classification. A Development CMS signature can therefore remain type 4,
requiring the association that AMFI skipped. The TXM finalizer at file
`0x32088` dispatches type 4 to file `0x31348`. That validator begins with:

```asm
ldr  x8, [x0, #0x108]   ; associated profile
cbz  x8, missing_profile
; native entitlements, TeamIdentifier and DeveloperCertificates checks
...
missing_profile:
mov  w0, #0x12a6
movk w0, #1, lsl #16   ; 0x112A6
; shared epilogue
```

The association helper stores the profile into signature `+0x108` at file
`0x32308`; disassociation clears it. The finalizer's type field is `+0x101`
and its finalized field is `+0x102`. The unique A6 error matches the launch
log and a host replay of the pristine instructions.

## Compatibility patch and limits

The new patch replaces the two instructions at file `0x313cc` with
`mov w0, #0xa6; nop`, returning this component's native success status only
from the null-profile exit. The native finalizer then stores type 4 and
returns 3. The patch does not invent a profile, change the category to 5/10,
or force the entire selector 24 handler to succeed.

Discovery requires the unique A6 error and shared epilogue, its single
null-profile predecessor, the existing non-null success/error convergence,
and the sole caller in the finalizer's type-4 arm. An extra predecessor,
changed dispatch, missing shape or ambiguity throws before any bytes are
applied. Both existing patches must be enabled. `findAll()` clears pending
records on a failed discovery, so a retry cannot apply only half the plan.

Missing-profile Apps consequently do not receive the entitlement, Team ID or
developer-certificate authorization that a profile would supply. Keeping
their CMS classification is not a substitute for that authorization. This
tradeoff is why the repair is an experimental option. When a profile is
associated, every native check of that profile remains in place.

## Verification

The focused Xcode tests cover relocated discovery, missing/ambiguous/modified
control flow, selection and version gates, and failure without partial
records. The complete-image tests pin the pristine TXM hash before executing
native code and check that only the reviewed 8-byte region differs.

Native replay uses both a generated installer signature and an optionally
supplied CMS-signed executable (`VPHONE_PROFILE_APP`). Type assignment and
policy callbacks are controlled inputs; this is not native CMS certificate
classification or a full launch. The original affected App's main executable
was supplied in the local run. Its results were:

| Controlled input | Original TXM | Only the new compatibility patch |
| --- | --- | --- |
| Profile validator, null profile | `0x112A6` | `0xA6` (success) |
| Finalizer, type 4, null profile | `0x112A6`, finalized type 0 | `3`, finalized type 4 |
| Finalizer, type 5, null profile | `3`, finalized type 5 | Same |
| Non-null, untrusted profile | `0x12225` | Same |
| Earlier platform-only policy | Rejected | Rejected |

The generated ldid signature independently hits `0x130A1` at the earlier
hash-flags check in pristine TXM. The isolated A6 patch preserves that rejection;
it does not replace the existing A1 bypass. Existing remap tests run the
combined plan, including that bypass, on ldid/ad-hoc admission, malformed
SuperBlobs, category behavior and library compatibility.

On 2026-11-10, the `FirmwarePatcherTests` workspace scheme passed **79 tests in
8 suites**, including both TXM suites and the required version, selection,
declaration, plan, gate and bundled-catalogue suites. Neither supplied-image
test was skipped. The complete-image coexistence comparison differs from
standard at only `0x313cc..<0x313d4`; standard's existing comparison still passes.
Other firmware reference-corpus tests were not run (`ipsws/ref_extract` is
absent). No restore, live TXM replacement, App re-signing or successful guest
launch is claimed.

The `VPhoneCommand` workspace build and catalogue check pass. The 13 TXM
tests passed again after adding the mapping-type getter assertion below.
For Xcode replay, set `TEST_RUNNER_VPHONE_REMAP_TXM` to the pinned raw TXM
and optionally `TEST_RUNNER_VPHONE_PROFILE_APP` to a CMS-signed Mach-O.

### Relationship to the lost-execute-permission regression

The original remap issue involved high-category restrictions after a fabricated
cache hit. XNU clears X on association failure while the map-insertion caller
discards the error; see [the remap investigation](txm_executable_remap.md).

The association handler at TXM file `0x1eb10` reads finalized type through the
native getter at `0x32360` (signature `+0x102`). The branch at `0x1ec14` routes
types below 6 to ordinary CodeDirectory bounds instead of the high-type
whole-executable-segment requirement. The main-image alias path at `0x1ee78`
also distinguishes types <=5 from higher types. The new patch leaves those
instructions and real cache queries intact. Its admitted type 4 stays type 4;
it does not restore a fabricated cache hit or force type 10.

The CMS replay calls that exact mapping-type getter and verifies that a newly
admitted signature publishes 4. This and the 8-byte-only image difference
support preservation of the remap fix; live page mapping remains unverified.

## Deployment

Use a new test VM and a bundle built from this change. For a test VM starting
from the standard preset, the intended selection is:

```zsh
vphone-cli fw set-patches cms-profile-test --preset standard --allow txm-exp-missing_profile
vphone-cli fw patches cms-profile-test
```

Check that both prerequisite patches are enabled, then include the new TXM in
that test VM's normal firmware-patch/restore workflow. `fw set-patches` alone
only changes intent. Current fleet delivers TXM through a restore; `cfw
update-kernel` and `cfw update-environment` do not install it. A restore erases
guest data, so do not use the existing development VM as the first experiment.

Runtime acceptance: first launch a small Development CMS-signed App and confirm
the A6 failure disappears. Then query actual destination RX and execute original
main/framework code after partial, whole and repeated-alias remaps. The earlier
remap PR's VM results do not validate this additional patch.
