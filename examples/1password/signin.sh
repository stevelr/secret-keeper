# sign into 1password
# add this to your .bashrc or .zshrc to create an alias op-signin.
# or source it 
#
# Once logged in you have 30 minutes to execute onepassword (op) comamnds
# until you need to re-sign in
#

#MY_PASS_ACCT="acme"

op-signin() {
    eval $(op signin $MY_PASS_ACCT)
}

