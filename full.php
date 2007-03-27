<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
//
// +----------------------------------------------------------------------+
// | PHP version 4.0                                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2004 The PHP Group                                     |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.02 of the PHP license,      |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Jeroen Derks <jeroen@derks.it>                              |
// +----------------------------------------------------------------------+
//
// $Id$

/**
 *	Test a range of different characters and sizes.
 *	Test a range of different characters and sizes.
 *
 *	@package		Crypt_Xtea_Test
 *	@modulegroup	Crypt_Xtea_Test
 *	@module			full
 *	@access			public
 *
 *	@version		$Revision$
 *	@since			2004/Oct/04
 *	@author			Jeroen Derks <jeroen@derks.it>
 */

/** Crypt_Xtea class */
require_once 'Crypt/Xtea.php';

$obj = new Crypt_Xtea();
$msg = $argv[1];

for ($i = 30; $i <= 34; ++$i)
{
    $key = '';
    for ($n = $i; $n < $i + $i; ++$n)
        $key .= chr($n);

    for ($j = 32; $j <= 64; ++$j)
    {
        $msg = '';
        for ($n = $j; $n < $j + $j; ++$n)
            $msg .= chr($n);

        $result	= $obj->encrypt($msg, $key);

        $tmp = join('', unpack('H*', $result));

        // output result
        printf("%3d.%3d: %s\n", $i, $j, $tmp);

        $result = $obj->decrypt($result, $key);
        if ($result != $msg)
            die("ERROR: decryption failed\n");
    }
}
?>
