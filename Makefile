PHP=php
PHP_CMD=$(PHP) $(PHP_FLAGS)
SCRIPTS=tester.php XteaTest.php

all:
	@echo No default target...

test:			test.dummy		
		

test.dummy:		$(SCRIPTS)
				nice -20 $(PHP_CMD) tester.php > test.out

profile:		profiled.dummy

profiled.dummy:	$(SCRIPTS)
				nice -20 $(PHP_CMD) tester.php 1 > profiled.out
