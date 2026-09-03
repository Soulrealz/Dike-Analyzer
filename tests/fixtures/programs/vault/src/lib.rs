use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;

    /// Creates the vault PDA that will hold deposited tokens for `admin`.
    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        ctx.accounts.vault.admin = ctx.accounts.admin.key();
        ctx.accounts.vault.amount = 0;
        ctx.accounts.vault.bump = bump;
        Ok(())
    }

    /// Deposits `amount` tokens into the vault, tracked in the `Vault` account.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let vault = &mut ctx.accounts.vault;
        vault.amount = vault.amount.checked_add(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }

    /// Withdraws `amount` tokens back to `admin`, gated by the vault's admin authority.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);
        require!(amount <= ctx.accounts.vault.amount, VaultError::InsufficientFunds);

        let admin_key = ctx.accounts.admin.key();
        let vault_seeds: &[&[u8]] = &[b"vault", admin_key.as_ref(), &[ctx.accounts.vault.bump]];
        let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.admin_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;

        let vault = &mut ctx.accounts.vault;
        vault.amount = vault.amount.checked_sub(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }

    /// Closes the vault, returning its rent lamports to `admin`.
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        require!(ctx.accounts.vault.amount == 0, VaultError::VaultNotEmpty);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8 + 1,
        seeds = [b"vault", admin.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.admin.as_ref()],
        bump = vault.bump,
        has_one = admin,
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub depositor_token_account: Account<'info, TokenAccount>,

    pub admin: SystemAccount<'info>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.admin.as_ref()],
        bump = vault.bump,
        has_one = admin,
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub admin_token_account: Account<'info, TokenAccount>,

    pub admin: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.admin.as_ref()],
        bump = vault.bump,
        has_one = admin,
        close = admin,
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub admin: Signer<'info>,
}

#[account]
pub struct Vault {
    pub admin: Pubkey,
    pub amount: u64,
    pub bump: u8,
}

#[error_code]
pub enum VaultError {
    #[msg("amount must be greater than zero")]
    InvalidAmount,
    #[msg("vault does not hold enough funds")]
    InsufficientFunds,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("vault must be empty before closing")]
    VaultNotEmpty,
}
