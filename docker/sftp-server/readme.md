docker build -t custom-sftp .


sftp -i ssh/sftp_ssh -P 2222 admin@localhost


if:
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

do:
ssh-keygen -f "/home/dik/.ssh/known_hosts" -R "[localhost]:2222"

or:
sftp -P 2222 admin@localhost

pw: testing321
