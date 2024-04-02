import json
from typing import Any, Union, List, Dict, Optional

import khayyam
from django.core import signing
from django.db.models import QuerySet, Model
from django.http import QueryDict
from django.utils.datetime_safe import datetime
from django.views import View

from .exceptions import ValueOutOfRangeError, ObjectNotFoundError, ParamNotFoundError, InvalidParamFormatError
from django.utils.translation import gettext as _
import re


class ManagerBase(View):
    def get_store(self) -> QueryDict:
        """
        Get params from request.
        :return: A dictionary of parameters passed by user
        :rtype: QueryDict
        """

        if self.request.method == 'GET':
            return self.request.GET
        elif self.request.method == 'POST':
            return self.request.POST
        return QueryDict()

    def resolve_ip_address(self) -> str:
        """
        Resolves requester ip address

        :return: User ip address
        """

        # Check if user is using a proxy
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

    # Class Properties
    ip_address = property(resolve_ip_address)
    store = property(get_store)
    body = property(lambda self: self.request.body)
    user = property(lambda self: self.request.user)
    staff = property(lambda self: self.user.is_staff)
    superuser = property(lambda self: self.user.is_superuser)
    logged_in = property(lambda self: self.user.is_authenticated)

    def get_int(
            self,
            name: str,
            raise_error: bool = False,
            default: int = 0,
            min_value: int = None,
            max_value: int = None) -> int:
        """
        Get "name" as int from request

        :param name: Name of the parameter.
        :param raise_error: Raises error if name not found in request.
        :param default: default value if raise error is set to False to return
        :param min_value: Min acceptable value
        :param max_value: Max acceptable value
        :return: requested value converted to int
        :rtype: int
        :raise: ParamNotFoundError
        """

        data = self.store.get(name)

        if data is None:
            return self._raise_invalid_param_error(name, raise_error, default)

        data = data.replace(",", "")
        if not data.isdigit():
            return self._raise_invalid_param_error(name, raise_error, default)

        int_data = int(data)
        # Now let's check for min and max values
        if min_value is True and int_data < min_value:
            return self._raise_min_max_error(name, raise_error, min_value, max_value, default)

        # Checking Max value
        if max_value is not None and int_data > max_value:
            return self._raise_min_max_error(name, raise_error, min_value, max_value, default)

        return int_data

    def get_string(
            self,
            name: str,
            raise_error: bool = False,
            default: str = "",
            min_len: int = 0,
            max_len: int = 0) -> str:
        """
        Get "name" from request as str

        :param name: Parameter name to retrieve
        :param raise_error: raise error if parameter was not found in request
        :param default: default value to return if parameter was not found
        :param min_len: Min len of str to accept
        :param max_len: Max len of str to accept
        :return: str parameter value
        :rtype: str
        :raise: ParamNotFoundError, ValueOutOfRangeError
        """

        res = self.store.get(name, "")

        if res == "":
            return self._raise_invalid_param_error(name, raise_error, default)

        if min_len and len(res) < min_len:
            return self._raise_min_max_error(name, raise_error, min_len, max_len, default)

        if max_len and len(res) > max_len:
            return self._raise_min_max_error(name, raise_error, min_len, max_len, default)

        return res

    def get_float(
            self,
            name: str,
            raise_error: bool = False,
            default: float = 0.0) -> float:
        """
        Get "name" as float

        :param name: name of the param
        :param raise_error: raise error if param not found
        :param default: default value if raise error is False
        :return: float value of "name" parameter
        :rtype: float
        """

        data = self.store.get(name, None)
        if data is None:
            return self._raise_invalid_param_error(name, raise_error, default)

        data = data.replace(",", "")
        rx = re.findall(r'(\d+)(\.?\d+)?', data)
        if len(rx) > 0:
            return float("".join([a[0] + a[1] for a in rx]))

        return self._raise_invalid_param_error(name, raise_error, default)

    def get_datetime(
            self,
            name: str,
            date_format: str = '%Y/%m/%d %H:%M',
            raise_error: bool = False,
            default: datetime = None) -> datetime:
        """
        Get date with format
        :param name: name of parameter
        :param date_format: date format to convert
        :param raise_error: raise error if param not found
        :param default: default date to return if raise error is False
        :return: datetime object
        :rtype: datetime.datetime
        """

        if not date_format:
            raise ValueError(("Parameter date_format is empty!",))

        data = self.store.get(name, None)
        if data is None:
            return self._raise_invalid_param_error(name, raise_error, default)

        try:
            res = datetime.strptime(data, date_format)
            return res
        except ValueError:
            return self._raise_format_error(name, date_format, raise_error, default)

    def get_file_size(
            self,
            name: str,
            raise_error: bool = False,
            default: float = 0) -> float:
        """
        Convert user input data to file size. e.g. User enters : 1024 MB, you will receive : 1024 * 1024 bytes

        :param name: name of the parameter
        :param raise_error: raise error if parameter not found
        :param default: Default value if raise_error is False
        :return: Size that user entered in bytes
        :rtype: int
        """

        user_data = self.store.get(name, "")

        if not user_data:
            return self._raise_invalid_param_error(name, raise_error, default)

        match = re.match(r'(?P<size>\d+(\.\d+)?)(?P<space>\s)*(?P<types>[MmKkGgTtPp]?)(?P<x>[Bb])?', user_data)
        if match is None:
            return self._raise_format_error(name, "2M", raise_error, default)
        try:
            res = match.groups()
            if len(res) < 4:
                return self._raise_format_error(name, "2M / 3G", raise_error, default)

            size, __, __, mode, __ = res[0], res[1], res[2], res[3], res[4]
            mods = ['', 'k', 'm', 'g', 't', 'p']
            real_size = float(size)
            if mode == '':
                return real_size

            for m in mods:
                if m.lower() == mode.lower():
                    break
                real_size *= 1024
            return real_size
        except ValueError:
            return self._raise_format_error(name, "2M or 3G", raise_error, default)

    def paginate(
            self,
            query_set: Union[List, QuerySet],
            data_name: str,
            extra: Dict = None,
            default_per_page: int = 20):
        """
        Paginate query set or list and returns it to use in a template. Queryset or data key name in dictionary is
        the same data_name provided. Per Page parameter is read from "pp" querystring. Current Page is also
        read from "cp" querystring.
        Result contains these keys:

        data_name: Contains paginated data
        next: Next number to pass to "cp" parameter to view next page.
        back: Back number to pass to "cp" parameter in querystring to view previous page
        current_page: Current page number
        pages: Total number of pages
        last_page: Number of last page to pass to "cp" parameter to view
        request: request object to build URL
        is_last_page: True if reached last page
        is_first_page: True if cp is on the first page
        total_result: Number of records to view
        next_pages: List of pages to view for the next pages. Each item must pass to cp param to view the page.
        back_pages: List of pages to view for previous pages. Each item must pass to cp param to view the pate.

        :param query_set: Queryset or list to paginate
        :param data_name: Key name of data in result dict
        :param extra: Extra data to include in result
        :param default_per_page: per page result if not pp parameter is not defined
        :return: Dict contains the result of paginate
        :rtype: Dict
        """

        if extra is None:
            extra = {}

        if query_set is None:
            return {}

        per_page = self.get_int('pp', False, default=default_per_page)
        current_page = self.get_int('cp', False, 0)
        if isinstance(query_set, QuerySet):
            query_len = query_set.count()
        else:
            query_len = len(query_set)
        if current_page:
            paging = self._get_paging_(query_len, int(current_page), int(per_page))
        else:
            paging = self._get_paging_(query_len, 0, int(per_page))
        res = query_set[paging['start']: paging['end']]
        next_link = paging['end']
        back_link = paging['back']
        current_page = paging['page']
        page_count = paging['page_count']
        last_page = (page_count - 1) * int(per_page)
        is_last_page = current_page == page_count
        is_first_page = current_page == 1

        # Calculate next and previous pages.
        links_to_show = 5
        if page_count <= 5:
            links_to_show = 10

        next_pages = {a: (a * current_page, (a - 1) * per_page) for a in
                      range(current_page, current_page + links_to_show) if 0 < a <= page_count}
        back_pages = {a - 1: (a - 1, (a - 2) * per_page) for a in range(current_page, current_page - links_to_show, -1)
                      if 1 < a <= page_count}
        back_pages = {k: back_pages[k] for k in sorted(back_pages.keys())}

        rx = {data_name: res,
              'next': next_link,
              'back': back_link,
              'current_page': current_page,
              'pages': page_count,
              'per_page': int(per_page),
              'last_page': last_page,
              'request': self.request,
              'is_last_page': is_last_page,
              'is_first_page': is_first_page,
              'total_result': query_len,
              'next_pages': next_pages,
              'back_pages': back_pages
              }

        rx.update(extra)
        return rx

    def get_decrypted_list(
            self,
            name: str,
            raise_error: bool = False,
            default: List = None) -> List:
        """
        Process request and find objects by name, decrypt and return in a list

        :param name: name of the collection to read
        :param raise_error: raise error if parameter not found
        :param default: default list to return if raise error is False
        :return: A list of decrypted data
        :rtype: List
        """

        x = self.store.getlist(name)

        if not x:
            return self._raise_invalid_param_error(name, raise_error, default)

        res = []
        for a in x:
            z = signing.dumps(a)
            if z:
                res.append(z)

        if len(res) < 1:
            return self._raise_invalid_param_error(name, raise_error, default)

        return res

    def get_int_list(self, name: str, raise_error: bool = False, default: List = ()) -> List:
        """
        Process the request and get a list of int

        :param name: The name of the parameter to check
        :param raise_error: False by default
        :param default: default return
        :return: list of ints
        :rtype: List
        """

        if default is None:
            default = []

        i_list = self.store.getlist(name)
        if not i_list:
            return self._raise_invalid_param_error(name, raise_error, default)

        return [int(item) for item in i_list if item.isdigit()]

    def get_regex(
            self,
            pattern: str,
            default_value: Optional[List[str]] = (),
            raise_error: Optional[bool] = False) -> List[str]:
        """
        Find parameters by a regex and returns a list of matched data.
        It's useful when you want read a list of parameters with a specific name pattern.

        :param pattern: regex pattern to match parameter names
        :param default_value: default value if noting found
        :param raise_error: raise error if not result found
        :return: a list of patched parameters with their values
        :rtype: List[str]
        """

        rx = re.compile(pattern, re.IGNORECASE)
        match_keys = []
        for k in self.store.keys():
            if rx.search(k):
                match_keys.append(k)
        if not match_keys:
            return self._raise_invalid_param_error("", raise_error, default_value)
        return match_keys

    def get_from_persian_date(
            self,
            name: str,
            date_format: str = '%Y/%m/%d %H:%M',
            raise_error: bool = False,
            default: khayyam.JalaliDatetime = None) -> khayyam.JalaliDatetime:
        """
        Converts inout to a persian datetime. Khayyam library is needed for this conversion.
        pip install khayyam

        :param name: Param name to convert
        :param date_format: datetime format of input
        :param raise_error: raise error if input was not found
        :param default: default value to return if raise_error is False
        :return: khayyam datetime object
        :rtype: khayyam.datetime
        """

        if not khayyam:
            raise ImportError(("khayyam is not installed. Please install it first by pip install khayyam",))

        if not date_format:
            raise ValueError(("date_format is not valid",))

        data = self.store.get(name, None)
        if not data:
            return self._raise_invalid_param_error(name, raise_error, default)

        try:
            return khayyam.JalaliDatetime.strptime(data, date_format)
        except ValueError:
            raise self._raise_format_error(name, date_format, raise_error, default)

    def get_email(
            self,
            name: str,
            raise_error: bool = False,
            default: str = None) -> str:
        """
        Get email from user input

        :param name: Parameter name to read
        :param raise_error: raise error if param not found
        :param default: Default value to return if raise error is False
        :return: Email address
        :rtype: str
        """

        data = self.store.get(name, None)
        if not data:
            return self._raise_invalid_param_error(name, raise_error, default)

        res = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,4}', data)
        if len(res) > 0:
            return res[0]

        return self._raise_format_error(name, "user@domain.com", raise_error, default)

    def get_decrypted_value(self, name: str, raise_error: bool = False, default: Any = None) -> Any:
        """
        Get the value of an encrypted data sent by user. This encrypted value must generated by django.signing.dumps
        This value is an int or str, but not big objects or queryset. For queryset it's better to use
        get_decrypted_object

        :param name: Param name
        :param raise_error: Raise error if parameter not found
        :param default: default unencrypted value
        :return: Any data
        :rtype: Any
        """

        encrypted_data = self.store.get(name, None)

        if encrypted_data is None:
            return self._raise_invalid_param_error(name, raise_error, default)

        try:
            res = signing.loads(encrypted_data)
            return res
        except Exception:
            return self._raise_invalid_param_error(name, raise_error, default)

    def get_decrypted_object(
            self,
            value: Dict,
            model_class: QuerySet,
            raise_error: bool = False,
            default: Any = None) -> Optional[Model]:
        """
        Data to decrypt and recover object from Database. You can encrypt PK of the row, then pass it these function
        with it's model class to recover the data from DB. If data is not exists, then an exception will raise.
        e.g. value={"pk": "abc"}, base_class=User. This will decrypts value first: "abc". Then
        calls base_class filter to find the object:
        User.objects.filter(**{"pk": decrypted("abc")})

        :param value: A dictionary contains a key and a value, { database_filed_name: encrypted_value }
        :param model_class: Model class to read data from
        :param raise_error: Raise error if data not found, or encryption is not valid
        :param default: default value if raise error was set to False
        :return: An object inherited from Model
        :rtype: Model
        """

        key, vl = value.popitem()

        try:
            decrypted_value = signing.loads(vl)
        except Exception:
            return self._raise_object_not_found(key, raise_error, default)

        if decrypted_value is None:
            return None

        res = model_class.objects.filter(**{key: vl}).first()
        if not res:
            return self._raise_object_not_found(key, raise_error, default)
        return res

    def decrypt_from_request(
            self,
            key_name: str,
            name: str,
            model_class: QuerySet,
            raise_error: bool = False,
            default: Model = None
            ) -> Optional[Model]:

        """
        Recover DB data from request.
        e.g. pk of User table is encrypted and is sent by user with "user_id" name. So that would be:
        decrypt_from_request("pk", "user_id", User)

        :param key_name: Model field name to match
        :param name: item name in QueryDict in GET or POST method
        :param model_class: Model class to find data from
        :param raise_error: Raise error if data not found
        :param default: Default value to return if raise error is False
        :return: an object inherited from Model
        """

        x = self.get_string(name, raise_error)

        if not x:
            return default
        res = self.get_decrypted_object({key_name: x}, model_class)
        return res

    def json(self) -> Dict:
        """
        Convert body of request into json. If method is GET or body is not set, then an empty dict will be the
        result

        :return: Returns body of request as json.
        :rtype: Dict
        """

        res = {}
        if self.request.method == 'GET' or len(self.request.POST) > 0 or not self.request.body:
            return res

        try:
            res = json.loads(self.request.body)
        except Exception:
            try:
                res = QueryDict(self.body)
            except Exception:
                pass
        return res

    @staticmethod
    def _get_paging_(list_len: int, start_point: int, per_page: int = 5) -> Dict:
        """
        Arithmetic for pagination

        :param list_len: Length of the list to paginate
        :param start_point: Start point to retrieve
        :param per_page: Results per page
        :return: A Dictionary contains parameters needed by paginate()
        """

        if per_page:
            block_count = int(per_page)
            if block_count == 0:
                block_count = 10
        else:
            block_count = 10
        if list_len == 0:
            sp = 0
            nx = 0
            p = 1
            pc = 1
            bp = -1
        elif list_len <= block_count:
            sp = 0
            nx = list_len
            p = 1
            pc = 1
            bp = -1
        elif (start_point + block_count) < list_len:
            if start_point == 0:
                sp = 0
            elif start_point == block_count:
                sp = block_count
            elif (start_point % block_count) == 0:
                sp = start_point
            else:
                sp = block_count + int(start_point / block_count) + 1
            nx = sp + block_count
            bp = start_point - block_count
            if bp < 0:
                bp = 0
            pc = int(list_len / block_count) + 1
            if (list_len % block_count) == 0:
                pc -= 1
            p = int((start_point + block_count) / block_count)
        else:
            sp = start_point
            bp = start_point - block_count
            if (list_len % block_count) == 0:
                nx = start_point + block_count
            else:
                nx = start_point + (list_len % block_count)
            p = int((start_point + block_count) / block_count)
            pc = int(list_len / block_count) + 1
            if (list_len % block_count) == 0:
                pc -= 1

        return {'start': sp, 'back': bp, 'page': p, 'page_count': pc, 'end': nx}

    @staticmethod
    def _raise_min_max_error(name: str, raise_error: bool, min_value: Any, max_value: Any, default: Any) -> Any:
        """
        Shortcut to raise min and max for value error
        :param name: Name of the parameter
        :param raise_error: raise error
        :param default: Default value when raise error is False
        :param min_value: Min value
        :param max_value: Max value
        :return: default_value if raise_error is set to False
        :rtype: Any
        """

        if raise_error:
            raise ValueOutOfRangeError(name, min_value, max_value)
        return default

    @staticmethod
    def _raise_invalid_param_error(name: str, raise_error: bool, default: Any) -> Any:
        """
        Shortcut to raise error or return default value
        :param name: name of the parameter to fill in exception
        :param raise_error: Raise error
        :param default: Default value to return
        :return: depends on the type of default value
        :rtype: Any
        :raise: ParamNotFoundException
        """

        if raise_error:
            raise ParamNotFoundError(_("Parameter is not valid"), name)
        return default

    @staticmethod
    def _raise_object_not_found(name: str, raise_error: bool, default_value: Any) -> Any:
        """
        Shortcut to raise ObjectNotFoundError
        :param name: param name
        :param raise_error: raise error or not?
        :param default_value: default value to return if raise error is False
        :return: Any
        :rtype: Any
        """

        if raise_error:
            raise ObjectNotFoundError(name)
        return default_value

    @staticmethod
    def _raise_format_error(name: str, valid_example: str, raise_error: bool, default: Any) -> Any:
        """
        Shortcut to raise format error

        :param name: Param name
        :param valid_example: A valid example of data to view to user
        :param raise_error: raiser error
        :param default: default value to return if raise error is False
        :return: Any depends on default value
        :rtype: Any
        """

        if raise_error:
            raise InvalidParamFormatError(name, valid_example)
        return default

