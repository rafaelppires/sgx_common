## Common SGX

Common glue code shared among several SGX projects

_Under development_

#### enclave helper files
`sgx_cryptoall`
`libc_mock/*`

#### native code helper files
`sgx_initenclave`
`sgx_errlist`
`sgx_cryptoall`
`utils`

Code that supports both must be compiled with `-DENABLE_SGX` for the enclave version. Native crypto stuff depends on `libcrypto++`

## License

Copyright 2017-2019 Rafael Pires

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
