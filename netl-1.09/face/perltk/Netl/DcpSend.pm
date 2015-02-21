package Netl::DcpSend;

use Socket;

sub xmit {
	$message = shift @_;
	die "usage: Netl::DcpSend::xmit($message [, $port])" unless defined $message;
	$port = shift @_ || 47;
	$len = length($message);
        $data = pack "Nna$len", $$, $len, $message;
        $proto = getprotobyname('udp') ||
                die "getprotobyname(): $!\n";
        socket(Socket_Handle, PF_INET, SOCK_DGRAM, $proto) ||
                die "socket(): $!\n";
        $iaddr = gethostbyname('localhost') ||
                die "gethostbyname(): $!\n";
        $sin = sockaddr_in($port, $iaddr) ||
                die "sockaddr_in(): $!\n";
        send(Socket_Handle, $data, 0, $sin) ||
                die "send(): $!\n";	
}

1;
