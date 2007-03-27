<?php
	//
	//	tester.php
	//
	//	$Header$
	//
	/**
	 *	@package	Crypt_Xtea_Test
	 *	@module		tester
	 *	@access		public
	 *
	 *	@version	$Revision$
	 *	@since		2002/Aug/28
	 *	@author		Jeroen Derks <jeroen@derks.it>
	 */

	// check parameter
	if (IsSet($_SERVER['argc']) && 1 < $_SERVER['argc'] && $_SERVER['argv'][1])
	{
		// check for xdebug presence to enable profiling
		if (extension_loaded('xdebug'))
		{
			xdebug_start_profiling();
			$profiling = true;
			echo "Profiling enabled.\n";
			flush();
		}
	}

	/** XteaTest class */
	require_once 'XteaTest.php';

	 
	$suite = new PHPUnit_TestSuite('Crypt_XteaTest');
	$result = PHPUnit::run($suite);
	echo $result->toString();

	// check for profiling to show results
	if ($profiling)
		xdebug_dump_function_profile(XDEBUG_PROFILER_FS_SUM);
	else
		Crypt_XteaTest::getTimings();
?>
