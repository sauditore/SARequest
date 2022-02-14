# SARequest
Simple, compact and useful library to read request parameters in django framework. 

## Install
There are 2 methods to install this:

1- Install with pip (Recommended and the easiest way)
```
pip install sa_request
```

2- Install from source code:
```
git clone https://github.com/sauditore/SARequest.git
python setup.py install
```

## Usage:
To use this library just create a class and inherit from sa_request main class

```python
from sa_request.helper import SARequest
from sa_request.exceptions import ParamNotFoundError, AuthNeedError


class ViewName(SARequest):
    
    def get(self, request):
        # Get int_name from query string
        user_int = self.get_int("int_name", False, 100)
        
        # Get str_name from query string. If data was not found then "default_data" will return
        user_str = self.get_str("str_name", False, "default_data")
        
        # Get float_name from query string. If data was not found then 1.1 will return
        user_float = self.float("float_name", False, 1.1)
        
        try:
            # If raise_error is set True, then default value ignored
            # and and exception will raise.
            str_data = self.get_str("parameter_name", True)
            
            # Checks for user permission. If permission not granted then
            # AuthError will raise
            self.validate_request(perm="user.add_user")
        except ParamNotFoundError as e:
            # A response will return to user
            return e.get_response()
        except AuthNeedError as e:
            # redirect user to auth_login view
            return e.get_response()
        # and other logics
```

### Basic Structure:
Most of the methods have a similar signature:

method(name, raise_error, default)

<ul>
<li>
name: Name of the parameter to read from query string or post data
</li>
<li>
raise_error: If data is not provided, then raise ParamNotFoundError error.
</li>
<li>default: If raise_error is set to False, then this value will return as result. </li>
</ul>

### Methods:

### get_int:
Get "name" as int from request:
```python
def get_int(name: str, 
            raise_error: bool = False,
            default: int = 0,
            min_value: int = None,
            max_value: int = None
            ) -> int:

```
<hr/>

### get_string:
Get "name" from request as str with min / max length validation
```python
def get_string(name: str,
               raise_error: bool = False,
               default: str = '',
               min_len: int = 0,
               max_len: int = 0) -> str:
```
<hr/>

### paginate:
Paginate query set or list and returns it to use in a template. Queryset or data key name in a dictionary is
the same ``data_name`` provided. Per Page parameter is read from ``pp`` querystring. Current Page is also
read from ``cp`` querystring.
Result contains these keys:

1- ``data_name``: Contains paginated data

2- ``next``: Next number to pass to ``cp`` parameter to view next page.

3- ``back``: Back number to pass to ``cp`` parameter in querystring to view previous page

4- ``current_page``: Current page number

5- ``pages``: Total number of pages

6- ``last_page``: Number of last page to pass to ``cp`` parameter to view

7- ``request``: request object to build URL

8- ``is_last_page``: True if reached last page

9- ``is_first_page``: True if cp is on the first page

10- ``total_result``: Number of records to view

11- ``next_pages``: List of pages to view for the next pages. Each item must pass to cp param to view the page.

12- ``back_pages``: List of pages to view for previous pages. Each item must pass to cp param to view the pate.


```python
def paginate(query_set: Union[List, QuerySet],
             data_name: str,
             extra: Dict = None,
             default_per_page: int = 10)
```
<hr/>

#### get_decrypted_list:
Process request and find objects by name, decrypt and return in a list
```python
def get_decrypted_list(name: str,
                       raise_error: bool = False,
                       default: List = None
                       ) -> List
```
<hr/>

#### get_int_list:
Process the request and get a list of int
```python
def get_int_list(name: str, 
                 raise_error: bool = False, 
                 default: List = ()
                 ) -> List
```
<hr/>

#### get_file_size:
Convert user input data to file size. e.g. User enters : 1024 MB, you will receive : 1024 * 1024 bytes

```python
def get_file_size(name: str,
                 raise_error: bool = False, 
                 default: float = 0
                 ) -> float
```
<hr/>

#### get_float:
Get "name" as float

```python
def get_float(name: str,
             raise_error: bool = False,
             default: float = 0.0
              ) -> float
```

<hr/>

### Bugs:
I would be happy if you help me find them.

### TODO:
Add more useful functions 
