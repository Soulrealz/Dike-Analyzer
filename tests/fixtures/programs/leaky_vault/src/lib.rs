// A deliberately vulnerable counterpart to `vault`, for exercising both
// tracks against code that should produce findings.
//
// NO Cargo.toml, by design: fixture programs are parsed as text and must
// never be built (see PROJECT_CONTEXT, "Quirks").
//
// Each handler below carries a defect from the tool's class vocabulary. The
// defects are written the way real ones appear — a plausible program that a
// reviewer has to read carefully — not as labelled examples.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fixture11111111111111111111111111111111111");

#[program]
pub mod leaky_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.admin = ctx.accounts.admin.key();
        vault.amount = 0;
        vault.bump = bump;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = vault.amount + amount;

        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token.to_account_info(),
            to: ctx.accounts.vault_token.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = vault.amount - amount;

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.admin = new_admin;
        Ok(())
    }

    /// Admin-gated in name only: `admin` signs, but nothing checks that the
    /// signer is the admin this vault actually stores. Any account willing to
    /// sign can set the fee. This is the fixture's `missing-authority-binding`
    /// case — the other handlers either take no signer at all (which is
    /// `missing-signer`, a different defect) or claim no authority role.
    pub fn set_fee(ctx: Context<SetFee>, fee: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = fee;
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub admin: Pubkey,
    pub amount: u64,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + 32 + 8 + 1, seeds = [b"vault", admin.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub depositor_token: Account<'info, TokenAccount>,
    pub depositor: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub caller: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    // No `has_one = admin`: the signer below is never matched against
    // `vault.admin`.
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub admin: Signer<'info>,
}
