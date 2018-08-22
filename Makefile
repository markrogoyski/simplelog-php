.PHONY : coverage lint setup tests

lint :
	vendor/bin/phpcs --standard=coding_standard.xml --ignore=vendor .

test :
	vendor/bin/phpunit --configuration=tests/phpunit.xml tests/

coverage :
	vendor/bin/phpunit --configuration=tests/phpunit.xml --coverage-text=php://stdout tests/
