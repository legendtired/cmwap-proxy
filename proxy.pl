#use strict;
#use warnings;
use IO::Socket::INET;
use IO::Select;
use POSIX;

use constant DEBUG => 0;
use constant BUFFER_SIZE => 2048;

use constant CONFIG_FILE => 'config.ini';
use constant HTTP_PORT => 80;
use constant IDLE_URL => 'http://www.baidu.com/';

$| = 1;

my @kids;

my %cfg;

my $version  = '2.0';

print "UGiA CMWAP PROXY SERVER V$version\n";
print "(C) 2007 UGiA.CN.\n\n";

parseConfig();

my $httpPort   = $cfg{'server'}{'http_port'}  || 2008;
my $socksPort  = $cfg{'server'}{'socks_port'} || 1081;

my $is_cmwap   = $cfg{'http'}{'is_cmwap'};

my $connect_to = $cfg{'other'}{'connect_to'};

my $proxy_host = '10.0.0.172';
my $proxy_port = 80;

my $socks_host = '';
my $socks_port = 0;

if ($cfg{'http'}{'http_proxy'} && $cfg{'http'}{'http_proxy'} =~ /^(.*?):(\d+)$/) {
    $proxy_host = $1;
    $proxy_port = $2;
}


if ($cfg{'socks'}{'socks_proxy'} && $cfg{'socks'}{'socks_proxy'} =~ /^(.*?):(\d+)$/) {
    $socks_host = $1;
    $socks_port = $2;
}

my $httpSock  = IO::Socket::INET->new(Listen => 5, LocalPort => $httpPort)  or die("Cannot initialize http proxy server!\n");
my $socksSock = IO::Socket::INET->new(Listen => 5, LocalPort => $socksPort) or die("Cannot initialize socks proxy server!\n");

for ($httpSock, $socksSock) {
    $_->blocking(0);
}


my $mainSel = new IO::Select($httpSock, $socksSock);

print "Http  proxy listening on port $httpPort ...\n";
print "Socks proxy listening on port $socksPort ...\n";

# check cmwap connection quality
if ($is_cmwap) {
    if ((my $pid = fork()) == 0) {
        $socksSock->close;
        $httpSock->close;
        checkPort();
        exit(0);
    }
    else
    {
        push @kids, $pid;
        $idle_time = 0;
    }
}

my $idle_time = 0;

while (1) {
    my @ready = $mainSel->can_read(5);
    
    if (@ready) {
        foreach my $sock (@ready) {

            my $newSock = $sock == $httpSock ? $httpSock->accept : $socksSock->accept;
             
            if ($newSock < 0)
            {
                die("Can not accept connection!\n");
            }            

            binmode $newSock;
            $newSock->autoflush(1);
            $newSock->blocking(0);

            if ((my $pid = fork()) == 0) {

                if ($socksSock && $sock == $socksSock) {
                    $socksSock->close;
                    doRequest($newSock, 2);
                } else {
                    $httpSock->close;
                    doRequest($newSock, 1);
                }

                exit(0);
            }
            else
            {
                push @kids, $pid;
            }
            
            $newSock->close;
        }
    }
    else {
        $idle_time += 5;
        
        if ($idle_time >= 900) {
            if ((my $pid = fork()) == 0) {
                $socksSock->close;
                $httpSock->close;
                noIdle();
                exit(0);
            }
            else
            {
                push @kids, $pid;
                $idle_time = 0;
            }
        }
    }

    reapChild();
}


$httpSock->close;
$socksSock->close;



sub reapChild{

      my @running;

      for my $pid (@kids) {
          my $code = waitpid($pid, POSIX::WNOHANG);

          if ($code == 0) {
              push(@running, $pid);
          }
          else {
              #
          }
      }

      @kids = @running;
}

sub doRequest {

    my ($sock, $type) = @_;
    
    my $step = 1;        
    my ($ver, $nmethods, $methods, $cmd, @dst_addr, $rsv, $atype, $dst_addr, $dst_port);
    
    # socks
    if ($type == 2 && !$socks_host) {
        while (1) {
            my $code = $sock->sysread($line, BUFFER_SIZE);
            
            DEBUG && print ">>> $line ";
            DEBUG && printX($line);

            if ($code <= 0) {
                last;
            }

            if ($step == 1) {
                ($ver, $nmethods, $methods) = unpack('C*', $line);
                
                if ($ver == 5) {
                    $sock->syswrite(pack("CC", $ver, $methods), 2);
                    $step = $methods != 0 ? 2 : 3;

                    next;
                }

                # socks 4
                ($ver, $cmd, $dst_port, @dst_addr) = unpack("C2nC4", $line);
                
                if ($cmd != 1) {
                    last;
                }

                # socks 4A
                if ($dst_addr[0] == 0 && $dst_addr[1] == 0 && $dst_addr[2] == 0 && $dst_addr[3] != 0) {
                    $extra = substr($line, 8);
                    ($userid, $dst_addr) = split("\x00", $extra);
                }
                else
                {
                    $dst_addr = join('.', @dst_addr);
                }

                last;
            }
            elsif ($step == 2)
            {
                $ver = unpack('C*', $line);
                $sock->syswrite(pack("C", $ver) . "\x00", 2);
                $step = 3;

                next;
            }
            elsif ($step == 3)
            {
                ($ver, $cmd, $rsv, $atype, $dst_addr, $dst_port) = unpack("C4A*X2n", $line);
                
                $dst_addr = substr($dst_addr, 0, -2);

                if ($cmd != 1) {
                    last;
                }
                
                if ($atype == 1) {
                    $dst_addr = inet_ntoa($dst_addr);
                }
                elsif ($atype == 3)
                {
                    $dst_addr = unpack("x1A*", $dst_addr);
                }
                elsif ($atype == 4)
                {
                    $dst_addr = inet_ntoa($dst_addr);
                }

                last;
            }
            #
        }
        
        # Connect cmd only
        if ($cmd != 1) {
            
            my $msg = $ver == 4 ? "\x00\x5b" : "\x05\x02";
            $sock->syswrite($msg, length($msg));
            
            DEBUG && print "<<< $msg\n";

            $sock->shutdown(0);
            $sock->close();

            return 0;
        }


        DEBUG && print "=== $ver, $cmd, $dst_addr, $dst_port\n";        

        if ($dst_port == HTTP_PORT) {
            my $msg = replayMsg($ver, $atype, $dst_addr, $dst_port);
            $sock->syswrite($msg, length($msg));

            DEBUG && print "<<< $msg\n";
        }
    }

    my $proxySock = IO::Socket::INET->new(PeerHost => $proxy_host, PeerPort => $proxy_port);

    if (!$proxySock) {
        if ($type == 2 && !$socks_host) {
            $msg  = $ver == 4 ? "\x00\x5b" : "\x05\x03\x00";
            $sock->syswrite($msg, length($msg));

            DEBUG && print "<<< $msg\n";
        }
        
        $sock->shutdown(0);
        $sock->close();
        
        return;
    }

    binmode $proxySock;
    $proxySock->autoflush(1);
    $proxySock->blocking(0);

    
    if ($type == 2 && !$socks_host && $dst_port != HTTP_PORT) {
        my $req = "CONNECT $dst_addr:$dst_port HTTP/1.0\r\nUser-Agent: UGiA CMWAP PROXY SERVER\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nContent-Type: image/gif\r\n\r\n";
        $proxySock->write($req, length($req));
        
        DEBUG && print ">>> CONNECT $dst_addr:$dst_port HTTP/1.1\n";

        my $established = 0;
        my $code = $proxySock->sysread(my $line, BUFFER_SIZE);
        
        DEBUG && print "<<< $line\n";
        #printX($line);

        if ($line =~/HTTP\/1\.[01] 200 /i) {
            $established = 1;
        }

        if ($established) {
            DEBUG && print "$dst_addr:$dst_port Connection established.\n";
            my $msg = replayMsg($ver, $atype, $dst_addr, $dst_port);
            $sock->syswrite($msg, length($msg));
            
            DEBUG && print "<<< $msg\n";
        }
        else
        {
            $msg  = $ver == 4 ? "\x00\x5b" : "\x05\x03\x00";
            $sock->syswrite($msg, length($msg));
            
            DEBUG && print "<<< $msg\n";

            $sock->shutdown(0);
            $sock->close();
            $proxySock->close();

            return 0;
        }
    }
    elsif ($type == 2 && $socks_host) {
        my $req = "CONNECT $socks_host:$socks_port HTTP/1.0\r\nUser-Agent: UGiA CMWAP PROXY SERVER\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nContent-Type: image/gif\r\n\r\n";
        $proxySock->write($req, length($req));
        
        DEBUG && print ">>> CONNECT $socks_host:$socks_port HTTP/1.1\n";

        my $code = $proxySock->sysread(my $line, BUFFER_SIZE);
        
        DEBUG && print "<<< $line\n";
    }

    # process requests

    DEBUG && print "-" x 80;
    
    $clientSock = $sock;

    my $sel = new IO::Select($clientSock, $proxySock);

    while (1) {
        my @ready = $sel->can_read(5);
        if (@ready) {
            foreach my $sock (@ready) {

                my $code = $sock->sysread(my $data, BUFFER_SIZE);

                if ($sock == $clientSock) {
                    DEBUG && print ">>> $data\n";
                    
                    if ($type == 2 && $dst_port == HTTP_PORT && $data =~ m/^Host: (.*?)\r\n/im) {
                        my $host = $1;
                        $data =~ s/^(GET|POST|HEAD|DELETE|PUT|TRACE) \//$1 http:\/\/$host\//im;
                    }

                    if (($type == 1 && $is_cmwap) || ($type == 2 && $dst_port == HTTP_PORT && $is_cmwap)) {
                        $data =~ s/^User-Agent: .*?\r\n/User-Agent: UGiA CMWAP PROXY\/1.0\r\n/im;
                    }

                    $proxySock->write($data, length($data));
                }
                else {
                    DEBUG && print "<<< $data\n";             

                    if (($type == 1 && $is_cmwap) || ($type == 2 && $dst_port == HTTP_PORT && $is_cmwap)) {
                        $data =~ s/^Content-Type: (application|text)\/(vnd|xhtml)[^;]*/Content-Type: text\/html/im;
                    }

                    $clientSock->write($data, length($data));
                }

                if ($code <= 0) {
                    $_->close for ($clientSock, $proxySock);

                    $clientSock = undef;
                    $proxySock  = undef;
                    
                    last;
                }

                #
            }
        }

        if (!$clientSock && !$proxySock) {
            exit(1);
        }
    }
    
    exit(1);
}

sub replayMsg
{
    my ($ver, $atype, $dst_addr, $dst_port) = @_;

    if ($ver == 4) {
        $msg  = "\x00\x5A";
        $msg .= pack("n", $dst_port);
        $msg .= inet_aton($dst_addr);
    }
    else
    {
        $msg  = "\x05\x00\x00";

        if ($atype == 0x01) {
            $msg .= pack("C", $atype);
            $msg .= inet_aton($dst_addr);
        }
        elsif ($atype == 0x03)
        {
            $atype = 1;
            $msg .= pack("C", $atype);

            #my ($name, $aliases, $addrtype, $length, @addrs) = gethostbyname($dst_addr);

            #$msg .= "@addrs";
            #$msg .= inet_aton(getHost($dst_addr));
            
            # fake ip
            $msg .= inet_aton('10.0.0.1');
        }
        elsif ($atype == 0x04)
        {
            $msg .= pack("C", $atype);
            $msg .= pack("C16", inet_aton($dst_addr));
        }
        
        $msg .= pack("n", $dst_port);
    }
    
    return $msg;    
}

sub parseConfig
{
    open CONFIG, '<' . CONFIG_FILE or die('Can not open config file!');
    
    my $key;
    while (<CONFIG>) {
        chomp;
        next if substr($_, 0, 1) eq ';' || $_ eq '';
        
        $line = $_;
        $line =~ s/^\s+|\s+$//;

        if ($line =~ m/\[(.*)?\]/s) {
            $key = $1;

            $key =~ s/^\s+|\s+$//;
            $cfg{$key} = {};
        }
        elsif ($line =~ m/(.*?)\s*=\s*([^;]*)?/) {
            $sub_key = $1;
            $sub_value = $2;
            
            $sub_key =~ s/^\s+|\s+$//;
            $sub_value =~ s/^\s+|\s+$//;
            $cfg{$key}{$sub_key} = $sub_value;
        }
    }
}

sub noIdle
{
    my $addr = shift;

    my $sock = IO::Socket::INET->new(PeerHost => '127.0.0.1', PeerPort => $httpPort);
    my $req = "GET " . IDLE_URL . " HTTP/1.1\r\nConnection: Close\r\n\r\n";
    $sock->syswrite($req, length($req));
    
    while (<$sock>) {
    }

    $sock->shutdown(0);
    $sock->close();
}

sub checkPort
{
    my $req = "CONNECT $connect_to HTTP/1.1\r\n\r\n";    
    my $established = 0;

    print "\nConnection quality: ";

    my $sock = IO::Socket::INET->new(PeerHost => $proxy_host, PeerPort => $proxy_port, Timeout => 5);

    if (!$sock) {
        print "Unknown\n";
        return;
    }

    $sock->autoflush(1);
    
    eval {
        local $SIG{ALRM} = sub { die "alarm\n" }; 
        alarm 5;
       
        $sock->syswrite($req, length($req));
        my $code = $sock->sysread(my $line, BUFFER_SIZE);
        
        #DEBUG && print "<<< $line\n";

        if ($line =~/HTTP\/1\.[01] 200 /i) {
            $established = 1;
        }

        alarm 0;
    };

    $sock->shutdown(0);
    $sock->close();
    
    if ($@ && $@ eq "alarm\n")
    {
        print "Unknown";
    }
    elsif ($established) {
        print "Unlimited";
    }
    else
    {
        print "Limited";
    }

    print "\n";
}

sub printX
{
    my $str = shift;    

    for (unpack("C*", $str)) {
        printf("0x%02X ", $_);
    }
    
    print "\n";
}