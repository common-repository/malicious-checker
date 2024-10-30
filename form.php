<?php
require_once('../../../wp-config.php');
global $wpdb;
/*
if($_GET['link_id']){
	$link_id = $_GET['link_id'];
	echo "link_id: $link_id<br>";

	$table_name = $wpdb->prefix . 'malicious_checker';

	$wpdb->insert( 
		$table_name, 
		array( 
			'time' => current_time( 'mysql' ), 
			'name' => "qq", 
			'text' => $link_id, 
		) 
	);
}
*/

if($_POST['link_id']){
	$link_id = $_POST['link_id'];	
	$version = $_POST['version'];
	$path = home_url();
	//$contents = file_get_contents($path."/".$link_id);
	$contents = file_get_contents(ABSPATH.$link_id);
	$md5 = md5($contents);
	echo "link_idx: $link_id<br>";
	echo "version: $version<br>";
	//echo "path: $path<br>";
	//echo "link: $path/$link_id<br>";
	//echo "md5: $md5<br>";
	//echo "contents: $contents<br>";
	//$p = getcwd();
	//echo "p: $p<br>";

	//$base = dirname(__FILE__);
	//echo "base: $base<br>";
	//echo fs_get_wp_config_path();

	//if ( !defined('GIGIPATH') )
    //define('GIGIPATH', dirname(__FILE__) . '/');
	//echo ABSPATH;

	//echo ABSPATH.$link_id;

	$table_name = $wpdb->prefix . 'malicious_checker';

	$wpdb->insert( 
		$table_name, 
		array( 
			'time' => current_time( 'mysql' ), 
			'file' => $link_id, 
			'version' => $version, 
			'md5' => $md5, 
		) 
	);
}
?>