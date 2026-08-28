#!/usr/bin/env bash
# PolinRider canary samples — known-positive bytes, NOT rules.
#
# Sourced by rules.sh. Deliberately a SEPARATE FILE from the rules it validates.
#
# These are fragments of the real carriers. A consumer plants them, runs its own
# rules against them, and refuses to report anything clean if a rule fails to
# fire. A scanner whose rules have drifted looks exactly like a clean machine;
# this is the only thing that separates the two.
#
# WHY NOT IN rules.sh
# They were, briefly. A single find-and-replace across that file rewrote a
# signature AND the sample proving it worked, in one pass, and the self-test
# kept passing on a rule that no longer matched any real carrier. Evidence that
# moves whenever the claim moves is not evidence. Editing rules.sh must not be
# able to touch this file.
#
# RULES FOR EDITING
# If the campaign rotates and a signature must legitimately change, update the
# sample here BY HAND, from a verified carrier. Never the other way round: never
# soften a sample to make a rule pass. A failing canary means the rules stopped
# matching real malware -- that is the finding, not the obstacle.
#
# Validated against the four byte-exact carriers supplied by the IR lead on
# 2026-08-27 (SHA256-verified, held outside any repo).

# Variant A / wave-1 shuffle build — carries POLINRIDER_SIGS_CORE[0].
POLINRIDER_CANARY_CORE='const s = "rmcej%otb%";'

# Variant C / wave-2 plain source — the implant's exact host-side usage.
POLINRIDER_CANARY_HOST='const src = atob(process.env.AUTH_API_KEY);'

# Variant B / obfuscator.io build — the quoted header key, with the surrounding
# bytes it really ships with. Quoted on purpose: an unquoted Sec-V: matches zero
# real payloads, so a sample without the quotes would validate the wrong rule.
POLINRIDER_CANARY_REPO="],'Sec-V':_0x3d94ba"

# Both build-number spellings the campaign has actually shipped. Two samples,
# not one: anchoring on the A prefix is a recorded way to go blind to variant A.
POLINRIDER_CANARY_MARKER_A="global['!']='9-3727-2';"
POLINRIDER_CANARY_MARKER_B='global.i="A9-3727-2";'

# Must match NOTHING. A rule that fires on everything detects nothing, and that
# failure is invisible without a negative control.
POLINRIDER_CANARY_NEGATIVE='ordinary source, nothing to see here'
