use std::time::Instant;

use crate::wireguard::state::{FlowEntry, ReverseRekeyStatus};

const SAFETY_SESSION_AGE_MAX_SECS: f64 = 220.0;
const SAFETY_SUPPRESS_TIME_MAX_SECS: f64 = 95.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyVerdict {
    Pass,
    Drop,
}

pub fn handle_outbound_hs(entry: &mut FlowEntry, now: Instant) -> RekeyVerdict {
    let established_time = entry.established_time.unwrap_or(now);
    let session_age = now.duration_since(established_time).as_secs_f64();

    match entry.rev_status {
        ReverseRekeyStatus::Done => {
            if !entry.rev_c3_warned {
                entry.rev_c3_warned = true;
                println!(
                    "  [REVERSE REKEY AUDIT] Notice: Client emitted Outbound 148 B in Cycle #3+ on flow {} (Passing)",
                    entry.flow_key
                );
            }
            RekeyVerdict::Pass
        }
        ReverseRekeyStatus::Fallback => RekeyVerdict::Pass,
        ReverseRekeyStatus::Init => {
            entry.rev_status = ReverseRekeyStatus::Suppressing;
            entry.rev_first_suppressed = Some(now);
            entry.rev_suppress_count = 1;

            println!("=========================================================================");
            println!("  [BETA REVERSE REKEY] CLIENT REKEY SUPPRESSED -> WAITING FOR SERVER");
            println!("-------------------------------------------------------------------------");
            println!("  Flow          : {}", entry.flow_key);
            println!("  Session Age   : {:.1} seconds", session_age);
            println!("  Strategy      : Suppressing Client Type 1 (148 B) to trigger Server Initiator");
            println!("  WireGuard Spec: 'Allow initiator and responder to swap roles'");
            println!("  Target Window : Server expected to initiate between ~175s and ~210s");
            println!("  Safety Timer  : Extended to {:.0}s (Tunnel protection)", SAFETY_SESSION_AGE_MAX_SECS);
            println!("=========================================================================\n");

            RekeyVerdict::Drop
        }
        ReverseRekeyStatus::Suppressing => {
            let first_suppressed = entry.rev_first_suppressed.unwrap_or(now);
            let time_suppressed = now.duration_since(first_suppressed).as_secs_f64();

            if session_age > SAFETY_SESSION_AGE_MAX_SECS
                || time_suppressed > SAFETY_SUPPRESS_TIME_MAX_SECS
            {
                entry.rev_status = ReverseRekeyStatus::Fallback;
                println!("=========================================================================");
                println!("  [BETA REVERSE REKEY] SAFETY FALLBACK TRIGGERED (Extended 220s Window)");
                println!("-------------------------------------------------------------------------");
                println!("  Flow          : {}", entry.flow_key);
                println!("  Elapsed       : {:.1}s (Suppressed for {:.1}s)", session_age, time_suppressed);
                println!("  Reason        : Server did not initiate within 220s window.");
                println!("  Action        : Allowing Client Rekey to pass directly (Tunnel preserved).");
                println!("=========================================================================\n");
                RekeyVerdict::Pass
            } else {
                entry.rev_suppress_count += 1;
                println!(
                    "  [BETA REVERSE REKEY] Client Rekey Retry #{} Suppressed (Session Age: {:.1}s / Window: {:.0}s) ---> DROPPED",
                    entry.rev_suppress_count, session_age, SAFETY_SESSION_AGE_MAX_SECS
                );
                RekeyVerdict::Drop
            }
        }
        ReverseRekeyStatus::ServerInitiated => RekeyVerdict::Pass,
    }
}

pub fn handle_inbound_hs(entry: &mut FlowEntry, _now: Instant) {
    if entry.rev_status != ReverseRekeyStatus::Done {
        entry.rev_status = ReverseRekeyStatus::ServerInitiated;
        println!("=========================================================================");
        println!("  [BETA REVERSE REKEY] SERVER INITIATION (Type 1 - 148 B) RECEIVED!");
        println!("-------------------------------------------------------------------------");
        println!("  Flow          : {}", entry.flow_key);
        println!("  Milestone     : Server has assumed the INITIATOR role on the wire!");
        println!("  Action        : Passing directly to Client with ZERO latency (0 ms)");
        println!("=========================================================================\n");
    }
}

pub fn handle_outbound_resp(entry: &mut FlowEntry, _now: Instant) {
    if entry.rev_status == ReverseRekeyStatus::ServerInitiated {
        entry.rev_status = ReverseRekeyStatus::Done;
        println!("=========================================================================");
        println!("  [BETA REVERSE REKEY] CLIENT RESPONSE (Type 2 - 92 B) DISPATCHED!");
        println!("-------------------------------------------------------------------------");
        println!("  Flow          : {}", entry.flow_key);
        println!("  Status        : ROLE SWAP FULLY ACCOMPLISHED & LOCKED!");
        println!("  Engine State  : Entering DEEP SLEEP (0% CPU, 0 ms added latency).");
        println!("                  On all subsequent cycles, Server will initiate rekeys.");
        println!("=========================================================================\n");
    }
}
