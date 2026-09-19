use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::Deal;

/// The most common guard shape in real Anchor code: a stored `Pubkey` field,
/// an account of the same name, and a constraint requiring them to match.
///
/// `deal` is derived from `maker`, not from `resolver`, so the derivation
/// pins one half of this struct and not the other. Remove the constraint and
/// any account at all may resolve any deal — which is what makes this a valid
/// mutation site, unlike `settle`, where the seeds already do the binding.
#[derive(Accounts)]
pub struct Resolve<'info> {
    pub resolver: Signer<'info>,

    /// CHECK: pinned by `deal`'s seeds.
    pub maker: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"deal", maker.key().as_ref()],
        bump = deal.bump,
        constraint = deal.resolver == resolver.key() @ EscrowError::Unauthorized,
    )]
    pub deal: Account<'info, Deal>,
}

pub fn handler(ctx: Context<Resolve>) -> Result<()> {
    let deal = &mut ctx.accounts.deal;
    deal.amount = 0;
    Ok(())
}
