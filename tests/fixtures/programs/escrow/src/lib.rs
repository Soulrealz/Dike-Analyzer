// A clean, multi-file Anchor program used as a mutation source.
//
// Every handler here forwards to a module, the way real programs are written.
// That matters to the analyzer: with delegation the handler body holds no
// state writes to reason from, and the accounts struct lives in a different
// file from the handler.
//
// Nothing in this program is a defect. A finding on it is a false positive and
// shows up in the eval as a non-zero noise floor.

use anchor_lang::prelude::*;

pub mod error;
pub mod instructions;
pub mod state;

pub use instructions::*;

declare_id!("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");

#[program]
pub mod escrow {
    use super::*;

    pub fn open_deal(ctx: Context<OpenDeal>, deal_id: u64, amount: u64, resolver: Pubkey) -> Result<()> {
        instructions::open_deal::handler(ctx, deal_id, amount, resolver)
    }

    pub fn resolve(ctx: Context<Resolve>) -> Result<()> {
        instructions::resolve::handler(ctx)
    }

    pub fn fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
        instructions::fund::handler(ctx, amount)
    }

    pub fn settle(ctx: Context<Settle>, amount: u64) -> Result<()> {
        instructions::settle::handler(ctx, amount)
    }

    pub fn set_fee(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
        instructions::set_fee::handler(ctx, fee_bps)
    }

    pub fn nominate_admin(ctx: Context<NominateAdmin>, new_admin: Pubkey) -> Result<()> {
        instructions::nominate_admin::handler(ctx, new_admin)
    }

    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        instructions::accept_admin::handler(ctx)
    }
}
