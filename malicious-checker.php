<?php
/*
Plugin Name: Malicious Checker
Plugin URI: https://wordpress.org/plugins/malicious-checker/
Text Domain: malicious-checker
Description: Malicious Checker scans all of your files for potentially malicious.
Author: Gabriel Ginard
Version: 1.2.7
Author URI: http://www.degabriel.net/malicious-checker/
*/

global $malicious_checker_install_db_version;
$malicious_checker_install_db_version = '1.2.7';


function malicious_checker_install() {
	global $wpdb;
	global $malicious_checker_install_db_version;

	$table_name = $wpdb->prefix . 'malicious_checker';
	
	$charset_collate = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE $table_name (
		id mediumint(9) NOT NULL AUTO_INCREMENT,
		time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
		file text NOT NULL,
		version text NOT NULL,
		md5 text NOT NULL,
		PRIMARY KEY  (id)
	) $charset_collate;";

	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
	dbDelta( $sql );

	add_option( 'malicious_checker_install_db_version', $malicious_checker_install_db_version );
}


function malicious_checker_install_data() {
	global $wpdb, $malicious_checker_install_db_version;

	$file = 'wp-content/plugins/malicious-checker/malicious-checker.php';
	$path = home_url();
	$contents = file_get_contents($path."/".$file);
	//$contents = file_get_contents(ABSPATH.$link_id);
	$md5 = md5($contents);
	
	$table_name = $wpdb->prefix . 'malicious_checker';
	
	$wpdb->insert( 
		$table_name, 
		array( 
			'time' => current_time( 'mysql' ), 
			'file' => $file, 
			'version' => $malicious_checker_install_db_version,
			'md5' => $md5, 
		) 
	);
}


function malicious_checker_deactivation() { // Deactivation plugin
	global $wpdb;
	$table_name = $wpdb->prefix . 'malicious_checker';
	$sql = "DROP TABLE IF EXISTS $table_name";
	$wpdb->query($sql);
	delete_option('malicious_checker_install_db_version');
}


function malicious_checker_uninstall() { // Uninstall plugin
	global $wpdb;
	$table_name = $wpdb->prefix . 'malicious_checker';
	$sql = "DROP TABLE IF EXISTS $table_name";
	$wpdb->query($sql);
	delete_option('malicious_checker_install_db_version');
}


register_activation_hook( __FILE__, 'malicious_checker_install' );
register_activation_hook( __FILE__, 'malicious_checker_install_data' );

//register_deactivation_hook(__FILE__, 'malicious_checker_deactivation');
register_uninstall_hook(__FILE__, 'malicious_checker_uninstall');


function md5_test($tfile, $version){
	global $wpdb;
	$contents = file_get_contents($tfile);
	$md5 = md5($contents);
	$md5db = trim($wpdb->get_var( "SELECT md5 FROM " . $wpdb->prefix . "malicious_checker where md5='$md5' and version='$version'" ));
	if ($md5db<>"") return false;

	return true;
}

function malicious_checker_check($array_files, $module_title, $module_directory, $version, $module_type) {
	//global $wpdb;
	$static_count = 0;
	$bad_lines = null;
	$static_urls = null;
	$static_count = 0;
	//echo "module_title: $module_title<br>";
	//echo "array_files: $array_files, module_title: $module_title, module_directory: $module_directory, module_type: $module_type<br>";
	//echo '<pre>';print_r($array_files);echo '</pre>';
	foreach ($array_files as $tfile) {		
		$lines = file($tfile, FILE_IGNORE_NEW_LINES); // Read the file into an array
		//echo "tfile: $tfile<br>";
		$line_index = 0;
		$is_first = true;
		foreach($lines as $this_line){
			if (stristr ($this_line, "base64")) {
				if (md5_test($tfile, $version)){
					if ($is_first) {
						$bad_lines .= malicious_checker_make_edit_link($tfile, $module_title, $module_directory, $version, $module_type);
						$is_first = false;
					}
					$bad_lines .= "<div class=\"malicious-checker-bad\"><strong>Line " . ($line_index+1) . ":</strong> \"" . trim(htmlspecialchars(substr(stristr($this_line, "base64"), 0, 95))) . "...\"</div>";
					//break;
				}
			}
			if (stristr ($this_line, "mapss")) {
				if (md5_test($tfile, $version)){
					if ($is_first) {
						$bad_lines .= malicious_checker_make_edit_link($tfile, $module_title, $module_directory, $version, $module_type);
						$is_first = false;
					}
					$bad_lines .= "<div class=\"malicious-checker-bad\"><strong>Line " . ($line_index+1) . ":</strong> \"" . trim(htmlspecialchars(substr(stristr($this_line, "mapss"), 0, 95))) . "...\"</div>";
					//break;
				}
			}
			if (stristr ($this_line, "\${")) {
				if (md5_test($tfile, $version)){
					if ($is_first) {
						$bad_lines .= malicious_checker_make_edit_link($tfile, $module_title, $module_directory, $version, $module_type); 
						$is_first = false;
					}
					$bad_lines .= "<div class=\"malicious-checker-bad\"><strong>Line " . ($line_index+1) . ":</strong> \"" . trim(htmlspecialchars(substr(stristr($this_line, "\${"), 0, 95))) . "...\"</div>";
					//break;
				}
			}
			if (stristr ($this_line, "*/include /*")) {
				if (md5_test($tfile, $version)){
					if ($is_first) {
						$bad_lines .= malicious_checker_make_edit_link($tfile, $module_title, $module_directory, $version, $module_type);
						$is_first = false;
					}
					$bad_lines .= "<div class=\"malicious-checker-bad\"><strong>Line " . ($line_index+1) . ":</strong> \"" . trim(htmlspecialchars(substr(stristr($this_line, "*/include /*"), 0, 95))) . "...\"</div>";
					//break;
				}
			}

			$line_index++;
		}
		
		$file_string = file_get_contents($tfile);

		$url_re='([[:alnum:]\-\.])+(\\.)([[:alnum:]]){2,4}([[:blank:][:alnum:]\/\+\=\%\&\_\\\.\~\?\-]*)';
		$title_re='[[:blank:][:alnum:][:punct:]]*';	// 0 or more: any num, letter(upper/lower) or any punc symbol
		$space_re='(\\s*)'; 

/*
		if (preg_match_all ("/(<a)(\\s+)(href".$space_re."=".$space_re."\"".$space_re."((http|https|ftp):\\/\\/)?)".$url_re."(\"".$space_re.$title_re.$space_re.">)".$title_re."(<\\/a>)/is", $file_string, $out, PREG_SET_ORDER))
		{
			$static_urls .= malicious_checker_make_edit_link($tfile, $module_title, $module_directory, $module_type); 
									  
			foreach( $out as $key ) {
				$static_urls .= "<div class=\"malicious-checker-ehh\">";
				$static_urls .= htmlspecialchars($key[0]);
				$static_urls .= "</div>";
				$static_count++;
			}			  
		}  
*/

	}
	
	if (!isset($bad_lines)) {
		$summary = '<span class="malicious-checker-good-notice">'.ucfirst($module_type).': Ok!</span>';
	} else {
		$summary = '<span class="malicious-checker-bad-notice">'.ucfirst($module_type).': Encrypted potentially malicious Code Found!</span>';
	}
	if(isset($static_urls)) {
		//$summary .= '<span class="malicious-checker-ehh-notice"><strong>'.$static_count.'</strong> Static Link(s) Found...</span>';
	}
	
	return array('summary' => $summary, 'bad_lines' => $bad_lines, 'static_urls' => $static_urls, 'static_count' => $static_count);

}


function malicious_checker_make_edit_link($tfile, $theme_title, $module_directory, $version, $module_type) {
	if ($module_type=="theme"){
		$theme_root = get_theme_root();
		$enlace = str_replace($theme_root, "", $tfile);
		$enlace = str_replace($module_directory, "", $enlace);
		$enlace = str_replace("\\", "/", $enlace);
		$enlace = str_replace("//", "", $enlace);
		$tfile = str_replace("\\", "/", $tfile);
		//$enlacesin = $enlace = str_replace($theme_root, "", $tfile);
		$enlacesin = substr(stristr($tfile, "wp-content"), 0);
		return "<div class=\"file-path\"><a href=\"theme-editor.php?file=" . $enlace . "&amp;theme=" . urlencode($module_directory) ."&amp;dir=theme\" target=_new>" . substr(stristr($tfile, "wp-content"), 0) . " [Edit]</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href='#' id='$enlacesin|$version' class='delete-link' target=_new>[OK FILE. DISABLE WARNING]</a></div>";
	}

	if ($module_type=="plugin"){
		$enlace = substr(stristr($tfile, "wp-content"), 0);
		$enlace = str_replace("\\", "/", $enlace);
		$enlacesin = str_replace("wp-content/plugins/", "", $enlace);
		return "<div class=\"file-path\"><a href=\"plugin-editor.php?file=" . $enlacesin . "\" target=_new>" . $enlace . " [Edit]</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href='#' id='$enlace|$version' class='delete-link' target=_new>[OK FILE. DISABLE WARNING]</a></div>";
	}

	return "";
}


function malicious_checker_get_files($template, $type) {
	// Scan through the template directory and add all php files to an array

	if ($type=="theme"){
		$theme_root = get_theme_root();
		$path = "$theme_root/$template";
	}

	if ($type=="plugin"){
		$aux = explode("/", $template);
		$template = $aux[0];
		$plugins = plugin_dir_path( __FILE__ );
		//echo "plugins: $plugins<br>";
		$my_plugin = WP_PLUGIN_DIR;
		$path = "$my_plugin/$template";
	}

	$template_files = array();
	$template_dir = @ dir($path);
	if ( $template_dir ) {
		$objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path), RecursiveIteratorIterator::SELF_FIRST);
		$i=0;
		foreach($objects as $name => $object){
			//echo "- $name<br>";
			if ( !preg_match('|^\.+$|', $name) && preg_match('|\.php$|', $name) ){
				$template_files[] = "$name";
				//echo "*$name<br>";
			}
		}
	}

	return $template_files;
}


function malicious_checker_init() {
	if ( function_exists('add_submenu_page') )
		$page = add_submenu_page('tools.php',__('Malicious Checker'), __('Malicious Checker'), 'update_plugins', 'malicious-checker.php', 'malicious_checker');
}

add_action('admin_menu', 'malicious_checker_init');






function malicious_checker() {

	?>
<script type="text/javascript">
	function toggleDiv(divid){
	  if(document.getElementById(divid).style.display == 'none'){
		document.getElementById(divid).style.display = 'block';
	  }else{
		document.getElementById(divid).style.display = 'none';
	  }
	}
</script>	

<h2><?php _e('Malicious Checker'); ?></h2>

<div class="pinfo">
	Malicious Checker scans all of your files for potentially malicious.<br/>
    For more info please go to the plugin page: <a href="http://degabriel.net/malicious-checker/">http://degabriel.net/malicious-checker/</a><br/>
</div>



<script type="text/javascript">
jQuery(document).ready(function($) {
	$(".delete-link").click(function(){
		var str = $(this).attr("id");
		var res = str.split("|");
		var link_id = res[0];
		var version = res[1];
		
		$.post('<?php echo WP_PLUGIN_URL . "/malicious-checker/form.php";?>', {'link_id':link_id, 'version':version}, function(data)
		{
			//parent.fadeOut('fast');
		});	
		return false;
	});
});
</script>


<div id="wrap">
    <?php
	echo "<br><b><u>--- PLUGINS ---</u></b><br>";
	$plugins = get_plugins();
	$plugin_names = array_keys($plugins);
	natcasesort($plugin_names);
	//echo '<pre>';print_r($plugins);echo '</pre>';
	foreach ($plugin_names as $plugin_name) {
		//echo "plugin_name: $plugin_name<br>";
		$title = $plugins[$plugin_name]['Name'];
		$version = $plugins[$plugin_name]['Version'];
		$author = $plugins[$plugin_name]['Author'];		
		$template_files_plugins = malicious_checker_get_files($plugin_name, "plugin");
		$results = malicious_checker_check($template_files_plugins, "", "", $version, "plugin");

		echo '<div id="malicious-checkerthemes">';
			echo '<div class="t-info">'."<strong>$title</strong>. Version: $version ";
			if ($results['bad_lines'] != '' || $results['static_urls'] != ''){
				echo '<input type="button" value="Details" class="button-primary" id="details" name="details" onmousedown="toggleDiv(\''.$title.'\');" href="javascript:;"/>';
			}
			echo '</div>';
			echo $results['summary']."<br>";
			echo '<div class="malicious-checkerresults" id="'.$title.'" style="display:none;">';
				echo $results['bad_lines'].$results['static_urls']."<br>";
			echo '</div>';
		echo '</div>';
	}
	//echo '<pre>';print_r($results);echo '</pre>';


	echo "<br><u><b>--- THEMES ---</b></u><br>";

	$themes = get_themes();
	$theme_names = array_keys($themes);
	natcasesort($theme_names);
	//echo '<pre>';print_r($themes);echo '</pre>';
	foreach ($theme_names as $theme_name) {
		//echo "theme_name: $themes[$theme_name]['Template']<br>";
		$title = $themes[$theme_name]['Title'];
		$version = $themes[$theme_name]['Version'];
		$author = $themes[$theme_name]['Author'];
		$template = $themes[$theme_name]['Template'];
		$template_files = malicious_checker_get_files($template, "theme");		
		$results = malicious_checker_check($template_files, $title, $template, $version, "theme");

		echo '<div id="malicious-checkerthemes">';
			echo '<div class="t-info">'."<strong>$title</strong>. Version: $version ";
			if ($results['bad_lines'] != '' || $results['static_urls'] != ''){
				echo '<input type="button" value="Details" class="button-primary" id="details" name="details" onmousedown="toggleDiv(\''.$title.'\');" href="javascript:;"/>';
			}
			echo '</div>';
			echo $results['summary']."<br>";
			echo '<div class="malicious-checkerresults" id="'.$title.'" style="display:none;">';
				echo $results['bad_lines'].$results['static_urls']."<br>";
			echo '</div>';
		echo '</div>';

	}
	echo '</div>';
}

// CSS to format results of themes check
function malicious_checker_css() {
echo '
<style type="text/css">
<!--

#wrap {
	background-color:#FFF;
	margin-right:5px;
}

.malicious-checker-bad,.malicious-checker-ehh {
	border:1px inset #000;
	font-family:"Courier New", Courier, monospace;
	margin-bottom:10px;
	margin-left:10px;
	padding:5px;
	width:90%;
}

.malicious-checker-bad {
	background:#FFC0CB;
}

.malicious-checker-ehh {
	background:#FFFEEB;
}

span.malicious-checker-good-notice, span.malicious-checker-bad-notice, span.malicious-checker-ehh-notice {
	float:left;
	font-size:120%;
	/*margin: 25px 10px 0 0;
	padding:10px;*/
	/*margin: 5px 2px 0 0;*/
	padding:3px;
}

span.malicious-checker-good-notice {
	background:#3fc33f;
	border:1px solid #000;
	width:90px;
	vertical-align: middle;
}

span.malicious-checker-bad-notice {
	background:#FFC0CB;
	border:1px solid #000;
	width:385px;
}

span.malicious-checker-ehh-notice {
	background:#FFFEEB;
	border:1px solid #ccc;
	width:210px;
}

.file-path {
	color:#666;
	font-size:12px;
	padding-bottom:1px;
	padding-top:5px;
	text-align:right;
	width:92%;
}

.file-path a {
	text-decoration:none;
}

.pinfo {
	background:#DCDCDC;
	margin:5px 5px 40px;
	padding:5px;
}

#malicious-checkerthemes {
	border-top:1px solid #ccc;
	/*margin:10px;
	min-height:100px;
	padding-bottom:20px;
	padding-top:20px;*/
	margin:10px;
	/*min-height:50px;*/
	min-height:20px;
	padding-bottom:10px;
	padding-top:10px;
}

#malicious-checkerthemes img,.malicious-checkernoimg {
	border:1px solid #000;
	color:#DCDCDC;
	float:left;
	font-size:16px;
	height:75px;
	margin:10px;
	text-align:center;
	width:100px;
}

.malicious-checkerresults {
	clear:left;
	margin-left:130px;
	
}

.t-info {
	display:inline;
	margin:10px;
}
-->
</style>
';
	}

add_action('admin_head', 'malicious_checker_css');


?>
