<?
include "/htdocs/phplib/trace.php";
include "/htdocs/phplib/phyinf.php";

fwrite("w", $START, "#!/bin/sh\n");
fwrite("w", $STOP,  "#!/bin/sh\n");

$cnt = query("/route/static/count");
foreach ("/route/static/entry")
{
	if ($InDeX > $cnt) break;

	$en	  = query("enable");
	$netid= query("network");
	$mask = query("mask");
	$gw   = query("via");
	$dev  = PHYINF_getruntimeifname(query("inf"));

	if ($en=="1" && $dev!="" && $netid!="" && $mask!="" && $gw!="")
	{
		if (ipv4networkid($netid,$mask)==$netid) $dest=$netid."/".$mask;
		else $dest=$netid;
		fwrite("a", $START, "ip route add ".$dest." via ".$gw." dev ".$dev." table STATIC\n");
	}
}
fwrite("a", $START, 'exit 0\n');

fwrite("a", $STOP, 'ip route flush table STATIC\n');
fwrite("a", $STOP, 'exit 0\n');
?>
