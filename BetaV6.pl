#! /usr/bin/perl -w
#use strict;
#use warnings;

use threads;
use threads::shared;

my $pcapture : shared = 0;
my $deathflag : shared = 0;
my $flag : shared = 0;
#Pcapture variables
my ($device,$filtertext,$wordtext, $roomname) :shared;
my $content : shared = "";
my $chatview : shared = "";
my $restview : shared = "";
my $cnt : shared = -1;
my @raw_data : shared = ();
my @keywords : shared = ();
my $keyword : shared = ();
my ($setlimit) : shared = "";
my $old :shared = "";
my $mcount : shared = 0;
my $startd : shared = 0;

#PC variables
my $filename : shared = "data.txt";
my $filename2 : shared = "report.txt";
my $filename3 : shared = "chatlog2.txt";
my $filename4 : shared = "alertwords.txt";

my $thread = threads->create (sub {
	while (! $deathflag) {
		if ($pcapture == 1){
			open FILE, ">$filename" or die $!;
			close (FILE);
			&capture($device);
		}
		else
		{
			threads->yield;
		}
	}
});

my $timer = threads->create (sub {
	while (! $deathflag) {
		if ($content ne $old)
		{
			&process();			
		}
		else
		{
			threads->yield;
		}
	}
});

#GUI Modules
use Glib qw/TRUE FALSE/;
use Gtk2 '-init';
use IO::File;
use Gtk2::Helper;

#Packet Modules
use Net::Pcap qw(:functions);
use NetPacket::TCP;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);

#Topic Detection Modules
use WordNet::QueryData;
use WordNet::Similarity::path;
use Text::English;
use Lingua::EN::Tagger qw( get_words );

#TD Variables
my $wn = WordNet::QueryData->new;
my $measure = WordNet::Similarity::path->new ($wn);

#Lingua information
my $postagger = new Lingua::EN::Tagger;


#Time variables
my @months;
my @weekDays;
my ($second, $theTime, $minute, $hour,$day, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings, $year);

#GUI variables
my ($Output, $fwlog, $WPentry, $mymailbox, $stuff, $display,$buffer);

#The higher the number the...
my $priority = 100000000;

#TD variables
my ($line, $msg);

#GUI
my $window = Gtk2::Window->new('toplevel');
$window->set_border_width(5);
$window->set_position('center_always');

#this vbox will return the bulk of the gui
my $vbox = &mainbox();		

$window->add($vbox);
$window->show();


#standard window creation, placement, and signal connecting
$window->signal_connect('delete_event' => sub { 
	if ($pcapture == 1) {
			warn "Disconnect the packet capture before closing.\n";
		} else {
			Gtk2->main_quit;
			$deathflag = 1;
			exit;
		}

		return 1;
	 });

Gtk2->main;
$window->destroy;
$timer->join;
$thread->join;
exit;

####################################################
sub mainbox()
{

	my $mainbox = Gtk2::HBox->new(FALSE,5);
	my $leftbox = Gtk2::VBox->new(FALSE,5);
	my $rightbox = Gtk2::VBox->new(FALSE,5);
	my $hand_cursor = Gtk2::Gdk::Cursor->new ('hand2');

#***************************************
#LeftBox
#Filter Information
	my $filtertable = Gtk2::Table->new (1, 2, FALSE);
	my $filterlabel = Gtk2::Label->new_with_mnemonic("Filter: ");
#$misc->set_alignment ($xalign, $yalign) 
	$filterlabel->set_alignment(1,0.5);
	$filtertable->attach_defaults ($filterlabel, 0, 1, 0,1);
	my $filterentry = Gtk2::Entry->new();
#get the original value 
	my $filter_orig = "(dst 127.0.0.1) && (tcp)";
	$filterentry->set_text($filter_orig);
	
	$filterentry->signal_connect (changed => sub {
		#need to share $filtertext
		my $filtertext = $filterentry->get_text;

	});

	$filterlabel->set_mnemonic_widget ($filterentry);
	$filtertable->attach_defaults($filterentry,1,2,0,1);

	$leftbox->pack_start($filtertable,0,0,4);

#*******************************************************************
#Device
	my $device_chooser_button = Gtk2::Frame->new('Device:');
	$device_chooser_button->set_border_width(3);
		
	my $combo_device = Gtk2::ComboBox->new_text();

	$combo_device->append_text("lo");
	$combo_device->append_text("eth0");
	$combo_device->append_text("wlan0");
	$combo_device->append_text("vboxnet0");
	$combo_device->set_active(1);
		
	$combo_device->signal_connect('changed' =>sub{

			$device = $combo_device->get_active_text;
	});
	$device_chooser_button->add($combo_device);
	$leftbox->pack_start($device_chooser_button,FALSE,TRUE,5);	
#*********************************************************************
#Word Limit
	my $wordtable = Gtk2::Table->new (1, 2, FALSE);
	my $wordlabel = Gtk2::Label->new_with_mnemonic("Message Limit: ");
	#$misc->set_alignment ($xalign, $yalign) 
	$wordlabel->set_alignment(1,0.5);
	$wordtable->attach_defaults ($wordlabel, 0, 1, 0,1);
	my $wordentry = Gtk2::Entry->new();
#get the original value 
	my $word_orig = "10";#&get_init_val();
	$wordentry->set_text($word_orig);
	
	$wordentry->signal_connect (changed => sub {
		
		$wordtext = $wordentry->get_text;

	});

	$wordlabel->set_mnemonic_widget ($wordentry);
	$wordtable->attach_defaults($wordentry,1,2,0,1);

	$leftbox->pack_start($wordtable,0,0,4);
#*********************************************************************
	
#TD Limit

	my $TDtable = Gtk2::Table->new (1, 2, FALSE);
	my $TDlabel = Gtk2::Label->new_with_mnemonic("TD Limit: ");
#$misc->set_alignment ($xalign, $yalign) 
	$TDlabel->set_alignment(1,0.5);
	$TDtable->attach_defaults ($TDlabel, 0, 1, 0,1);
	my $TDentry = Gtk2::Entry->new();
#get the original value 
	my $TD_orig = "7";#&get_init_val();
	$TDentry->set_text($TD_orig);
	
	$TDentry->signal_connect (changed => sub {

		my $TDtext = $TDentry->get_text;
	});

	$TDlabel->set_mnemonic_widget ($TDentry);
	$TDtable->attach_defaults($TDentry,1,2,0,1);

	$leftbox->pack_start($TDtable,0,0,4);	
	
	
#Related Value
	my $RVtable = Gtk2::Table->new (1, 2, FALSE);
	my $RVlabel = Gtk2::Label->new_with_mnemonic("Related Value: ");
#$misc->set_alignment ($xalign, $yalign) 
	$RVlabel->set_alignment(1,0.5);
	$RVtable->attach_defaults ($RVlabel, 0, 1, 0,1);
	my $RVentry = Gtk2::Entry->new();
#get the original value 
	my $RV_orig = "0.14";#&get_init_val();
	$RVentry->set_text($RV_orig);
	
	$RVentry->signal_connect (changed => sub {

		my $RVtext = $RVentry->get_text;
	});

	$RVlabel->set_mnemonic_widget ($RVentry);
	$RVtable->attach_defaults($RVentry,1,2,0,1);

	$leftbox->pack_start($RVtable,0,0,4);
	
#**
#Related Value
	my $CRtable = Gtk2::Table->new (1, 2, FALSE);
	my $CRlabel = Gtk2::Label->new_with_mnemonic("Chat Room Name: ");
#$misc->set_alignment ($xalign, $yalign) 
	$CRlabel->set_alignment(1,0.5);
	$CRtable->attach_defaults ($CRlabel, 0, 1, 0,1);
	my $CRentry = Gtk2::Entry->new();
#get the original value 
	my $CR_orig = "#test";#&get_init_val();
	$CRentry->set_text($CR_orig);
	
	$CRentry->signal_connect (changed => sub {

		my $CRtext = $CRentry->get_text;
	});

	$CRlabel->set_mnemonic_widget ($CRentry);
	$CRtable->attach_defaults($CRentry,1,2,0,1);

	$leftbox->pack_start($CRtable,0,0,4);	
#*********************************************************************

#Show the filechooserbuttons (open and select-folder action types)
	my $chatlog_chooser_button = Gtk2::Frame->new('Choose a Chatlog');
	$chatlog_chooser_button->set_border_width(3);

	my $hbox_chatlog_chooser_button = Gtk2::HBox->new(FALSE,5);
	$hbox_chatlog_chooser_button->set_border_width(5);

#Open a file dialog button----->
	my $chatlog_btn_file =Gtk2::FileChooserButton->new ('select a file' , 'open');
	$chatlog_btn_file->set_filename("$filename3"); #Chatlog.txt
	$hbox_chatlog_chooser_button->pack_start($chatlog_btn_file,TRUE, TRUE,5);
	
#Pack the chatlog button into the vbox
	$chatlog_chooser_button->add($hbox_chatlog_chooser_button);
	$leftbox->pack_start($chatlog_chooser_button,FALSE,TRUE,5);	

#*******************************************************************
	
#Show the filechooserbuttons (open and select-folder action types)
	my $report_chooser_button = Gtk2::Frame->new('Choose a Report Name');
	$report_chooser_button->set_border_width(3);

	my $hbox_report_chooser_button = Gtk2::HBox->new(FALSE,5);
	$hbox_report_chooser_button->set_border_width(5);

#Open a file dialog button----->
    my $report_btn_file =Gtk2::FileChooserButton->new ('select a file' , 'open');
	$report_btn_file->set_filename("$filename2"); #Report.html
	$hbox_report_chooser_button->pack_start($report_btn_file,TRUE,TRUE,5);

#Pack the button into the vbox
	$report_chooser_button->add($hbox_report_chooser_button);
	$leftbox->pack_start($report_chooser_button,FALSE,TRUE,5);
#*********************************************************************
#Show the filechooserbuttons (open and select-folder action types)
	my $alertlist_chooser_button = Gtk2::Frame->new('Alert File');
	$alertlist_chooser_button->set_border_width(3);

	my $hbox_alertlist_chooser_button = Gtk2::HBox->new(FALSE,5);
	$hbox_alertlist_chooser_button->set_border_width(5);

#Open a file dialog button----->
	my $alertlist_btn_file =Gtk2::FileChooserButton->new ('select a file' , 'open');
	$alertlist_btn_file->set_filename("$filename4"); #Alertlist.txt
	$hbox_alertlist_chooser_button->pack_start($alertlist_btn_file,TRUE, TRUE,5);
	
#Pack the chatlog button into the vbox
	$alertlist_chooser_button->add($hbox_alertlist_chooser_button);
	$leftbox->pack_start($alertlist_chooser_button,FALSE,TRUE,5);	
#*********************************************************************
#Set up the Connect Button
	#my $thr;
	my $execute = Gtk2::Button->new("Connect");
	$execute->signal_connect(clicked => sub 
	{ 
		$filtertext = $filterentry->get_text;
		$setlimit = $wordentry->get_text;
		$roomname = $CRentry->get_text;
		$filename2 = $report_btn_file->get_filename;
		$filename3 = $chatlog_btn_file->get_filename;
		$filename4 = $alertlist_btn_file->get_filename;
		#$setlimit = $wordtext;
		$pcapture = 1;
		$cnt = -1;
		#Create chatlog
		&report();
	});
	
 #Display the Connect Button
	$leftbox->pack_start($execute,FALSE,FALSE,6);
	$execute->can_default(TRUE);
#**********************************************************************
#Set up the Disconnect Button
	my $stop= Gtk2::Button->new("Disconnect");
	$stop->signal_connect(clicked => sub 
	{ 
		$pcapture = 0;
		$cnt = 1;
	});
	
 #Display the disconnect Button
	$leftbox->pack_start($stop,FALSE,FALSE,6);
	$stop->can_default(TRUE);
#**********************************************************************

#Set up the Close Button
	my $close= Gtk2::Button->new("Close");
	$close->signal_connect(clicked => sub 
	{ 
			if ($pcapture == 1) {
			warn "Disconnect the packet capture before closing.\n";
		} else {
		$window->destroy;
		Gtk2->main_quit;
		$pcapture = 0;
		$cnt = 1;
		$deathflag = 1;
	}
	});
#Display the Close Button
	$leftbox->pack_end($close,FALSE,FALSE,6);
	$close->can_default(TRUE);
########################################################################
#RightBox

#Chat Stream
	my $chatframe = Gtk2::Frame->new("Chat Stream");

#method of Gtk2::Container
	$chatframe->set_border_width(5);


	my $cstream = Gtk2::ScrolledWindow->new (undef, undef);
	$cstream->set_shadow_type ('etched-out');
	$cstream->set_policy('automatic', 'automatic');

	$cstream->set_size_request (800, 400);
	$cstream->set_border_width(5);

	my $chatview = Gtk2::TextView->new();
	$chatview->set_wrap_mode ('word');

	$chatview->set_editable(FALSE);
	my $fh = new IO::File;
	#Need something to update the filename after it changes
	my $pid = $fh->open ("./$filename3");
	Glib::IO->add_watch ( fileno $fh, 'in',sub{ 
	my ($fd,$condition,$fh) = @_;
 	#call 'watch_callback' to handle the incoming data	
 	\&watch_callback($fh,$chatview);
	},$fh, $priority);
	

	
	my $buffer = $chatview->get_buffer();

#create a mark at the end of the buffer, and on each
#'insert_text' we tell the textview to scroll to that mark
	$buffer->create_mark ('end', $buffer->get_end_iter, FALSE);
	$buffer->signal_connect (insert_text => sub {
		$chatview->scroll_to_mark ($buffer->get_mark ('end'),0.0, TRUE, 0, 0.5);
		if ($startd == 1)
		{
			my $TDtext = $TDentry->get_text;
			my $RVtext = $RVentry->get_text;
			&analyse($TDtext,$RVtext);
			$startd = 0;
		}
		if ($flag == 1)
		{
			&alertbox($keyword);
			$flag = 0;
		}
	});

	$cstream->add($chatview);
	$chatframe->add($cstream);
	$rightbox->pack_start($chatframe,TRUE,TRUE,4);

###################################################################
#Topic Results
	my $resultframe = Gtk2::Frame->new("Topic Results");

#method of Gtk2::Container
	$resultframe->set_border_width(5);

	my $tresults = Gtk2::ScrolledWindow->new (undef, undef);
	$tresults->set_shadow_type ('etched-out');
	$tresults->set_policy('automatic', 'automatic');

	$tresults->set_size_request (800, 200);
	$tresults->set_border_width(5);

	my $restview = Gtk2::TextView->new();

	$restview->set_editable(FALSE);


	my $fh2 = new IO::File;
	my $pid2 = $fh2->open ("./$filename2");

	Glib::IO->add_watch ( fileno $fh2, 'in',sub{ 
		my ($fd,$condition,$fh2) = @_;
 	#call 'watch_callback' to handle the incomming data	
		\&watch_callback2($fh2,$restview);
	},$fh2, $priority);
	
	my $buffer2 = $restview->get_buffer();

#create a mark at the end of the buffer, and on each
#'insert_text' we tell the textview to scroll to that mark
	$buffer2->create_mark ('end', $buffer2->get_end_iter, FALSE);
	$buffer2->signal_connect (insert_text => sub {
		$restview->scroll_to_mark ($buffer2->get_mark ('end'),0.0, TRUE, 0, 0.5);
	});

	$tresults->add($restview);
	$resultframe->add($tresults);
	$rightbox->pack_start($resultframe,TRUE,TRUE,4);

##################
	$mainbox->pack_start($leftbox, FALSE,FALSE,5);
	$mainbox->pack_start($rightbox,FALSE,FALSE,5);
##################
	$mainbox->show_all();
	return $mainbox;
}


####################################################
sub capture()
{
	my $err;

#   Use network device passed in program arguments or if no 
#   argument is passed, determine an appropriate network 
#   device for packet sniffing using the 
#   Net::Pcap::lookupdev method

	my ($dev) = @_;
	unless (defined $dev) {
		$dev = Net::Pcap::lookupdev(\$err);
		if ( defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
		}
	}

#   Look up network address information about network 
#   device using Net::Pcap::lookupnet - This also acts as a 
#   check on bogus network device arguments that may be 
#   passed to the program as an argument

	my ($address, $netmask);
	if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
		die 'Unable to look up device information for ', $dev, ' - ', $err;
	}


#   Create packet capture object on device

	my $object;
	$object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
	unless (defined $object) {
		die 'Unable to create packet capture on device ', $dev, ' - ', $err;
	}

#   Compile and set packet filter for packet capture 
#   object 

	my $filter;
	Net::Pcap::compile(
		$object, 
		\$filter,
		"$filtertext",
		0, 
		$netmask
	) && die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($object, $filter) &&
    die 'Unable to set packet capture filter';

#   Set callback function and initiate packet capture loop
	
	Net::Pcap::loop($object, $cnt, \&syn_packets, '') ||
		die 'Unable to perform packet capture';


	Net::Pcap::close($object);

	return 0;
}

sub syn_packets {
	if ($pcapture == 1)
	{
		my ($object,$header,$packet) = @_;
		my $ip = NetPacket::IP->decode(eth_strip($packet));
		my $tcp = NetPacket::TCP->decode($ip->{data});
		my $payload = $tcp->{data};

		if ( $payload =~ /PRIVMSG/ )
		{
			#print "Payload:\n$payload\n";
			$content = $payload;
		}
	}
	else
	{
		return 0;
	}
}


sub process()
{
			$now = &Time;
			$old = $content;
			&alert($content);
			#Write the information to the file for topic detection 
			open FILE, ">>$filename" or die $!;
			print FILE "$content";
			close (FILE);
			#Write information to chatlog
			$pdata = &write($content);
			open FILE3, ">>$filename3" or die $!;
			print FILE3 "$now $pdata";
			close (FILE3);
			push(@raw_data, $content);
#return $payload and push in the main program
			print "Limit is $setlimit\n";
			print "count is now $mcount\n";
#For every $payload returned count can go up
			$mcount++;
			if($mcount eq $setlimit)
			{
#thread then started from main program				
				$startd = 1;
				$mcount = 0;
				@raw_data = ();
			}
	return 0;
}

sub write()
{
	my ($data) = @_;
	my $chname = 'PRIVMSG '.$roomname.' :';
	
	($usname,$msg)=split(/$chname/,$data);
	
	#Remove unwanted stuff

			$usname =~ s/[A-Za-z0-9#$%&'*+\=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum|co\.uk|ac\.uk)\b//g;
			$usname =~ s/[A-Za-z0-9#$%&'*+\=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\=?^_`{|}~-]+)*@\b//g;
			$usname =~ s/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b//g;
			$usname =~ s/[\!|\(|\)|:]//g;
#Remove spaces
			$usname =~ s/^\s+|\s+$//g;
#turn to lower case 
			#$usname = lc $usname;
	
	if ($usname eq "")
	{
		$usname = "User";
	}
	
	$data = $usname." says: ".$msg;
	
	return $data;

}

sub alert()
{
	my ($content) = @_;
	my @words = ();
	
	open(FILE4, $filename4) || die("Could not open file!");
	@alert=<FILE4>;
	close (FILE);
	
	
	foreach $string (@alert)
	{
		@words=split(/,/,$string);
	}	

	foreach $word (@words)
	{	
		$word =~ s/\?|!|:|;|\.|"|_|,|\r|\n//g;
		if (! $word)
		{
			
		}
		else
		{
			if ($content =~ m/$word/i)
			{
				$flag = 1;
				$keyword = "$word found in $content";
				push(@keywords, $keyword);
			}
		}
	}
	return 0;
}

sub alertbox()
{
my ($keyword) = @_;	
	
my $awindow = Gtk2::Window->new;
$awindow->set_border_width(5);
$awindow->set_position('center_always');
$awindow->set_title('Alert');
$awindow->signal_connect(
	'delete_event' => sub { $awindow->destroy; }
);
$now = &Time; 
my $label = Gtk2::Label->new_with_mnemonic("$now: $keyword");
$label->set_line_wrap (1);
$awindow->add($label);
  
$awindow->show_all;
}

####################################################

sub watch_callback()
{
	my ($fh,$chatview) = @_;
	my @lines = $fh->getlines;
	foreach $line (@lines)
	{
		$msg = $line;
		my $buffer = $chatview->get_buffer();
		&update_buffer($buffer,$msg);
	}

#always return TRUE to continue the callback
return TRUE;
}

sub watch_callback2()
{
	my ($fh2,$restview) = @_;
	my @lines = $fh2->getlines;
	foreach $line (@lines)
	{
		#$restview = $thisview;
		$msg = $line;
		my $buffer2 = $restview->get_buffer();
		&update_buffer2($buffer2,$msg);
	}

return TRUE;
}

sub update_buffer {
 
 	my ($buffer,$msg)= @_;

 	 	my $iter = $buffer->get_end_iter;
 		Gtk2::TextBuffer::insert($buffer, $iter, $msg); 
	return 0;
}

sub update_buffer2 {
 
 	my ($buffer2,$msg2)= @_;

 		my $iter2 = $buffer2->get_end_iter;
 		Gtk2::TextBuffer::insert($buffer2, $iter2, $msg2); 
 	return 0;
}

sub report()
{
	#my($INtext,$CNtext,$NCtext) = @_;
	$now = &Time;
	open FILE3, ">>$filename3" or die $!;
	print FILE3 "\nChat Log Started: $now\n";
	#print FILE3 "Users in Chat:\n";

	#&Time;

	close (FILE3);
	return 0;
}

sub htmlfoot()
{
	print STDOUT "</br>\n";
	print STDOUT "Notes Closed At ";
	&Time;
	print STDOUT"</body>\n</html>";
}

sub Time()
{
	#my ($filename)= @_;
	@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	@weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
	($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings) = localtime();
	$year = 1900 + $yearOffset;
#Make sure the seconds, minutes and hours all have 0 infront if they are less than 10
	if ($second < 10)
	{
		$second = "0$second";
	}
	if ($minute< 10)
	{
		$minute = "0$minute";
	}
	if ($hour < 10)
	{
		$hour = "0$hour";
	}
	$theTime = "$hour:$minute:$second, $weekDays[$dayOfWeek] $months[$month] $dayOfMonth, $year";
#Print the time to the file
	#print STDOUT "$theTime "; 
	return $theTime;
}

sub analyse()
{
	

my ($line, $trash, $msg, $word, $cword, $found, $i, $value, $topic, $tagged, $uword, $stem);
my $chname = 'PRIVMSG '.$roomname.' :';
my @words = ();
my @ipadd = ();
my @eadd = ();
my @htmlist = ();
my @unames = ();
my @final = ();
my @topic = ();
my @stems = ();
my @raw_data2 = ();
my %freq = ();
my %topics = ();
	
#Open a file and read contents
	open(FILE, $filename) || die("Could not open file!");
	@raw_data2=<FILE>;
	close (FILE);
	
	my ($TD,$RV )= @_;
#Go through each line or if it was straight from part1 $payload
	foreach $line (@raw_data2)
	{
#Remove everything not a part of chat	
		($trash,$msg)=split(/$chname/,$line);
		
#Tokenise the words
		#@words=split(/\s/,$msg);
		if(! $msg)
		{
			#ignore
		}
		else
		{
#Tokenise the words
			@words=split(/\s/,$msg);
		
		
			foreach $word (@words)
			{
#Check for IP addresses
				if($word =~ m/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)
				{
					push(@ipadd, $word);
					$word =~ s/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b//g;
				}
#Check for Email Addresses
				elsif($word =~ /[a-z0-9!#$%&'*+\=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum|co\.uk|ac\.uk)\b/)
				{
					push(@eadd, $word);
					$word =~ s/[a-z0-9!#$%&'*+\=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum|co\.uk|ac\.uk)\b//g;
				}
#Check for website addresses
				elsif($word =~ /^(http|https|ftp):\/\/([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(\:[0-9]+)*(\/($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+))*$/)
				{
					push(@htmlist, $word);
					$word =~ s/^(http|https|ftp):\/\/([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(\:[0-9]+)*(\/($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+))*$//g;
				}
		
				$word = lc $word; # turn to lower case before calling:
#remove everything not needed
				$word =~ s/\?|!|:|;|\.|"|_|,//g;
				$word =~ s/^hi$/hello/;
	
				my $tagged = $postagger->add_tags($word);
				if (! $tagged)
				{
					#print null
				}
				elsif ($tagged ne "")
				{
					$freq{$tagged}++; 
				}
			}
#Obtain usernames
#Remove unwanted stuff
			$trash =~ s/[A-Za-z0-9#$%&'*+\=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum|co\.uk|ac\.uk)\b//g;
			$trash =~ s/[\!|\(|\)|:]//g;
#Remove spaces
			$trash =~ s/^\s+|\s+$//g;
#turn to lower case 
			$trash = lc $trash;
			if ($trash eq "")
			{
				$trash = "User";
			}
#Check to see if the name is in the list
			if (grep {m|^$trash?$|} @unames) {  }
			else
			{
#Add the name to the list
				push(@unames, $trash);
			}
		}
	}
# Loop through hash of words
	foreach my $word ( keys %freq) {	
#Check to see if the frequency is more than 10
		if ( $freq{$word} >= $TD )
		{
			if (($word =~ /^<nn>[\w]*<\/nn>|^<nns>[\w]*<\/nns>|^<nnp>[\w]*<\/nnp>|^<vb>[\w]*<\/vb>|^<vbd>[\w]*<\/vbd>|^<vbg>[\w]*<\/vbg>|^<vbn>[\w]*<\/vbn>|^<vbp>[\w]*<\/vbp>|^<vbz>[\w]*<\/vbz>/) && ($word !~ /(lol)|(rofl)|(action)|(heh)/gi) && ($word ne ""))
			{
#remove tags and spaces
				$word =~ s/<nn>|<\/nn>|<nns>|<\/nns>|<nnp>|<\/nnp>|<ppc>|<\ppc>|<vb>|<\/vb>|<vbd>|<\/vbd>|<vbg>|<\/vbg>|<vbn>|<\/vbn>|<vbp>|<\/vbp>|<vbz>|<\/vbz>//g;
				$word =~ s/^\s+|\s+$//g;
				foreach $uword (@unames)
				{
#check to see if word matches the username and remove it
					$word =~ s/^$uword//gi;
				}
				
				if ( grep( /^$word$/,@final) ){}
				else
				{
					push(@final, $word);
				}
			}
		}
	}
#Stem the words
	@stems = Text::English::stem( @final );
#Check if the words are in the array
	foreach $stem (@stems)
	{
		if ( grep( /^$stem$/,@final) ){	} #Get another word if its in the array
		else
		{
#If it isn't in the array add it
			push(@final, $stem); 
		}
	}


#Create the list of topics
	foreach $cword (@final)
	{
		if ($cword ne "")
		{
			$topic = $cword;
			push (@{ $topics{$topic} }, "$cword");
		}		
	}

#Loop through the topics
	foreach $topic ( keys %topics ) {
		$i = 0;
#Loop through the list
		foreach $i ( 0 .. $#{ $topics{$topic} } ) 
		{
			foreach $cword (@final)
			{
				if ($cword ne "")
				{
					$value = $measure->getRelatedness("$cword#n#1", "$topic#n#2");
					my ($error, $errorString) = $measure->getError();
					if (! $value)
					{
							#print "value is null";
							#$value = 0;
					}
					elsif (($value >= $RV) && ($cword ne "$topic"))
					{
							print "$cword (sense 1) <-> $topic(sense 2) = $value\n" unless $error;
							(@{ $topics{$topic}[$i] }) = "$cword";
							$i++;
					}
				}
			}
		}
	}

			open FILE2, ">>$filename2" or die $!;
			#print FILE "$content";
			#
	print FILE2 "\n\t\t\tTopic Detection Report\n";
	$now = &Time;		
	print FILE2 "Started: $now\n";
	print FILE2 "\t\tSettings Used \n";
	print FILE2 "Device: $device\tMessage Limit: $setlimit\tTD Limit: $TD\tRelated Value: $RV\n";
	print FILE2 "Chat Room: $roomname\n";
	print FILE2 "Users in Chat: \n";
	foreach my $name (@unames)
	{
		print FILE2 "\t$name\n";
	}
	print FILE2 "Frequently Occurring Words: \n";
	# Output hash in a descending numeric sort of its values
	foreach my $word ( sort { $freq{$a} <=> $freq{$b} } keys %freq) {
	#foreach my $word ( keys %freq) {
		if ( $freq{$word} >= $TD )
		{
			#$word =~ s/<nn>|<\/nn>|<nns>|<\/nns>|<nnp>|<\/nnp>|<ppc>|<\ppc>|<vb>|<\/vb>|<vbd>|<\/vbd>|<vbg>|<\/vbg>|<vbn>|<\/vbn>|<vbp>|<\/vbp>|<vbz>|<\/vbz>//g;
			print FILE2 "\t$word - $freq{$word}";
			print FILE2 "\n";
		}
	}
	print FILE2 "Keywords appearing in Chat:\n";
	foreach my $keyword (@keywords)
	{
		print FILE2 "$keyword";
	}
	print FILE2 "Related Words:\n";
# print the whole thing
	foreach $topic ( keys %topics ) {
		#print "$topic: ";
		print FILE2 "$topic: ";
		foreach $i ( 0 .. $#{ $topics{$topic} } ) 
		{
			print FILE2 "@{ $topics{$topic}[$i] } ";
		}
			#print "\n";
			print FILE2 "\n";
	}
close (FILE2);
undef $topic;
undef $i;
undef %freq;
undef %topics;
return 0;
#Stop Words Removed	
}
