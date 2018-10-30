# sslyze-lambda :lock: :key: #

[![Build Status](https://travis-ci.com/dhs-ncats/sslyze-lambda.svg?branch=develop)](https://travis-ci.com/dhs-ncats/sslyze-lambda)

`sslyze-lambda` contains code to build an AWS Lambda function that
utilizes [`sslyze`](https://github.com/nabla-c0d3/sslyze) to check
that hosts are not using outdated or insecure cryptographic ciphers.

## Example ##

Building the AWS Lambda zip file:
1. `cd ~/dhs-ncats/sslyze-lambda`
2. `docker-compose down`
2. `docker-compose build`
3. `docker-compose up`

## Note ##

Please note that the corresponding Docker image _must_ be rebuilt
locally if the script `build.sh` changes.  Given that rebuilding the
Docker image is very fast (due to Docker's caching) if the script has
not changed, it is a very good idea to _always_ run the
`docker-compose build` step when using this tool.

## License ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
