import codecs
import datetime
import mimetypes
import re
import os
import json
from typing import Dict, Any, List, Union, Optional, Tuple, Type

from django.shortcuts import redirect, render

from .exceptions import ParamNotFoundError, ValueOutOfRangeError, RequestValidationError, \
    InvalidParamFormatError, ObjectNotFoundError, AuthNeedError

try:
    import khayyam
except ImportError:
    khayyam = None

from datetime import date

from uuid import uuid4

import unicodedata
from django.core import signing
from django.contrib.auth.models import User
from django.db.models import QuerySet, Model
from django.http import HttpResponse, QueryDict, JsonResponse, HttpResponseRedirect
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext as _
from django.views import View


class FileUploadResult(object):
    """
    Contains information about uploaded files.
    """

    def get_user(self) -> str:
        """
        Username who uploaded file
       :return: username of the user
        :rtype: str
        """

        return self._user

    def get_upload_date(self) -> str:
        """
        Upload date of file
        :return:
        """

        return self._upload_date

    def get_path(self):
        return self._upload_path

    def get_file_name(self):
        return self._upload_file

    def get_file_size(self):
        return self._file_size

    user_id = property(get_user)
    upload_date = property(get_upload_date)
    upload_path = property(get_path)
    file_name = property(get_file_name)
    file_size = property(get_file_size)

    def __init__(self, user, upload_date, upload_path, file_name, file_sz):
        self._user = user
        self._upload_file = file_name
        self._upload_path = upload_path
        self._upload_date = upload_date
        self._file_size = file_sz


class SARequest(View):
    """
    Class to handle generic requests
    """

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

    # Class Properties
    store = property(get_store)
    body = property(lambda self: self.request.body)
    user = property(lambda self: self.request.user)
    staff = property(lambda self: self.user.is_staff)
    superuser = property(lambda self: self.user.is_superuser)
    logged_in = property(lambda self: self.user.is_authenticated)

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

    def response_render(self, template_path: str, context: Optional[Dict] = None) -> HttpResponse:
        """
        Return rendered HTML

        :param template_path: path of html
        :param context: context data
        :return: Rendered HTML
        :rtype: HttpResponse
        """

        return render(self.request, template_path, context=context)

    def get_int(self, name: str,
                raise_error: bool = False,
                default: int = 0,
                min_value: int = None,
                max_value: int = None
                ) -> int:
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

        rx = re.search(r'\d+', data)
        if rx is None:
            return self._raise_invalid_param_error(name, raise_error, default)
        res = int(rx.group())

        # Now let's check for min and max values
        if min_value is not None:
            if res < min_value:
                return self._raise_min_max_error(name, raise_error, min_value, max_value, default)

        # Checking Max value
        if max_value is not None:
            if res > max_value:
                return self._raise_min_max_error(name, raise_error, min_value, max_value, default)

        # Let's end this game
        return res

    def get_string(self, name: str,
                   raise_error: bool = False,
                   default: str = '',
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

        res = self.store.get(name, None)

        if res is None:
            return self._raise_invalid_param_error(name, raise_error, default)

        if min_len:
            if len(res) < min_len:
                return self._raise_min_max_error(name, raise_error, min_len, max_len, default)
        if max_len:
            if len(res) < max_len:
                return self._raise_min_max_error(name, raise_error, min_len, max_len, default)
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

    def paginate(self, query_set: Union[List, QuerySet],
                 data_name: str,
                 extra: Dict = None,
                 default_per_page: int = 10):
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
        next_pages = {a: (a-1) * per_page for a in range(current_page, current_page + 5) if 0 < a <= page_count}
        back_pages = {a-1: (a - 2) * per_page for a in range(current_page, current_page - 5, -1) if 1 < a < page_count}
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

    def get_decrypted_list(self, name: str,
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

        res = []
        for a in i_list:
            z = re.findall(r'\d+', a)
            res.append(int(z[0]))

        return res

    def get_file_size(self, name: str,
                      raise_error: bool = False, default: float = 0) -> float:
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

        x = re.match(r'(?P<size>\d+(\.\d+)?)(?P<space>\s)*(?P<types>[MmKkGgTtPp]?)(?P<x>[Bb])?',
                     user_data)

        if x is None:
            return self._raise_format_error(name, "2M 3G", raise_error, default)
        try:

            res = x.groups()
            if len(res) < 4:
                return self._raise_format_error(name, "2M 3G", raise_error, default)

            size, points, space, mode, extra = res[0], res[1], res[2], res[3], res[4]
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
            return self._raise_format_error(name, "2M 3G", raise_error, default)

    def get_float(self, name: str,
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

        rx = re.findall(r'\d+\.?\d+', data)
        if len(rx) > 0:
            return float(rx[0])
        return self._raise_invalid_param_error(name, raise_error, default)

    def get_date(self, name: str,
                 date_format: str = '%Y/%m/%d %H:%M',
                 raise_error: bool = False,
                 default: datetime.datetime = None) -> datetime.datetime:
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
            res = datetime.datetime.strptime(data, date_format)
            return res
        except ValueError:
            return self._raise_format_error(name, date_format, raise_error, default)

    def get_from_persian_date(self,
                              name: str,
                              date_format: str = '%Y/%m/%d %H:%M',
                              raise_error: bool = False,
                              default: khayyam.JalaliDatetime = None) -> datetime:
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

    def get_email(self, name: str,
                  raise_error: bool = False, default: str = None) -> str:
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

    def get_target_user(self,
                        name: str = 'u',
                        raise_error: bool = False,
                        default: str = None
                        ) -> User:

        """
        Get user object from request. This can be passed by a parameter in query string or post.
        :param name: name of parameter. Default is "u". Note "u" is int
        :param raise_error: Raise error if user not found
        :param default: Default user object to return if raise error is False
        :return: User object
        :rtype: User
        """

        target_id = self.get_int(name, raise_error)
        user = User.objects.filter(pk=target_id).first()
        if not user:
            return self._raise_invalid_param_error(name, raise_error, default)

        # Security Check
        # If current logged-in user is:
        # 1- Superuser: then no validation is required.
        # 2- Staff: Staff user can access lower users but not top users
        # 3- None of them:
        #
        # note: Superuser is has staff flag too.
        if self.request.user.is_staff:
            if self.request.user.is_superuser:
                return user
            elif user.is_superuser:
                return self._raise_object_not_found(name, raise_error, default)

            # user is staff or a normal user
            return user

        # User is not staff and not superuser, so it must be a normal user. So he can access same level user
        # At this point permission validation is at your own or use validate_request to check user can access
        # other objects or not!
        elif user.is_staff:
            return self._raise_object_not_found(name, raise_error, default)
        return user

    def get_decrypted_value(self,
                            name: str,
                            raise_error: bool = False,
                            default: Any = None) -> Any:

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

    def get_decrypted_object(self,
                             value: Dict,
                             model_class: QuerySet,
                             raise_error: bool = False,
                             default: Any = None
                             ) -> Optional[Model]:

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

    def decrypt_from_request(self,
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

        if self.request.method == 'GET' or len(self.request.POST) > 0 or not self.request.body:
            return {}
        try:
            res = json.loads(self.request.body)
            return res
        except Exception:
            return {}

    def handle_upload(self,
                      base_path: str,
                      add_date: bool = False,
                      add_user: bool = False,
                      random_name: bool = False
                      ) -> List[FileUploadResult]:
        """
        Handles sent file by user and saves it into base_path. You can also add date, username and
        choose if save file with it's original name or a random name.

        :param base_path: base folder path to store data. This path MUST exists.
        :param add_date: If set to True, then a folder with name of today will created.
        :param add_user: If set to True, then a folder with username of file uploader will created.
        :param random_name: If set to True, the file name will be set to a random name.
        :return: A list of uploaded files with their properties.
        :rtype: List[FileUploadResult]
        """

        # Creating base folders
        if not os.path.exists(base_path):
            os.mkdir(base_path)
        today = str(date.today())
        if add_date:
            today_path = os.path.join(base_path, today)
            if not os.path.exists(today_path):
                os.mkdir(today_path)
        else:
            today_path = base_path
        if add_user:
            if not self.request.user.is_authenticated():

                # if user is not authenticated, then use ALL as the name
                user_path = os.path.join(today_path, 'ALL')
            else:
                user_path = os.path.join(today_path, str(self.request.user.pk))
            if not os.path.exists(user_path):
                os.mkdir(user_path)
        else:
            user_path = base_path
        res = []

        # Start to write files
        for f in self.request.FILES:
            try:
                n = str(self.request.FILES.get(f))
                if random_name:
                    t = os.path.join(user_path, str(uuid4()))
                else:
                    t = os.path.join(user_path, n)
                a = codecs.open(t, 'w+b')
                for d in self.request.FILES[f]:
                    a.write(d)
                a.close()
                file_size = os.stat(t).st_size
                uid = 0
                if self.request.user.is_authenticated():
                    uid = self.request.user.pk
                res.append(FileUploadResult(uid, today, t, n, file_size))
            except Exception:
                continue
        return res

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

    ip_address = property(resolve_ip_address)

    @staticmethod
    def slugify(value: str):
        """
        Slugify data from request

        :param value: Value to slugify. e.g. site title
        :return: Slugify value
        :rtype: str
        """

        value = unicodedata.normalize('NFKC', value)
        value = re.sub(r'[^\w\s-]', '', value.lower()).strip()
        return re.sub(r'[\s]+', '-', value)

    def respond_as_attachment(self,
                              file_path: str,
                              original_filename: str
                              ) -> HttpResponse:
        """
        Response file to user. This method is good for small chunks of file.

        :param file_path: File path to read
        :param original_filename:  Original name of the file
        :return: HttpResponse
        :rtype: HttpResponse
        """

        if original_filename is None:
            original_filename = 'unknown_file'

        fp = codecs.open(file_path.encode('utf-8'), 'rb')
        response = HttpResponse(fp.read())
        fp.close()
        f_type, encoding = mimetypes.guess_type(original_filename)
        if f_type is None:
            f_type = 'application/octet-stream'
        response['Content-Type'] = f_type
        response['Content-Length'] = str(os.stat(file_path.encode('utf-8')).st_size)
        if encoding is not None:
            response['Content-Encoding'] = encoding

        # To inspect details for the below code, see http://greenbytes.de/tech/tc2231/
        if u'WebKit' in self.request.META['HTTP_USER_AGENT']:
            # Safari 3.0 and Chrome 2.0 accepts UTF-8 encoded string directly.
            filename_header = 'filename=%s' % original_filename

        elif u'MSIE' in self.request.META['HTTP_USER_AGENT']:
            # IE does not support internationalized filename at all.
            # It can only recognize internationalized URL, so we do the trick via routing rules.
            filename_header = ''
        else:
            # For others like Firefox, we follow RFC2231 (encoding extension in HTTP headers).
            filename_header = 'filename*=UTF-8\'\'%s' % original_filename
        response['Content-Disposition'] = 'attachment; ' + filename_header
        return response

    def validate_request(self,
                         methods: Tuple = ('get', 'post'),
                         check_referer: bool = False,
                         auth: bool = False,
                         superuser: bool = False,
                         staff: bool = False,
                         perm: str = ''
                         ) -> None:
        """
        Validate request against referer, auth, and permissions.
        E.g. validate_request(staff=True, perm="user.add_user|user.change_user")

        :param methods: Acceptable methods. it's not usable for class base views.
        :param check_referer: Check if user entered the address directly or with a link.
        :param auth: Check if the user is authenticated or not. if not AuthenticationNeededError will raise
        :param superuser: Check if the user is superuser or not. If not RequestValidationError will raise
        :param staff: Check if the user is staff or not. if not RequestValidationError will raise
        :param perm: Checks for a specified permission. Multi perm can be separated with a pip ( | )
        :return: None
        """

        request = self.request
        if request.method.lower() not in methods:
            raise RequestValidationError(_('Invalid request Method'), ())
        if check_referer:
            rx = request.META.get('HTTP_REFERER')
            if not rx:
                raise RequestValidationError(_('Direct Call is not permitted'), ())
            if request.build_absolute_uri('/') not in rx:
                raise RequestValidationError(_('You can not bypass site structure'), ())

        if auth:

            if not request.user.is_authenticated:
                raise AuthNeedError(request)
        if superuser:
            if not request.user.is_superuser:
                raise AuthNeedError(request)
        if staff:
            if not request.user.is_staff:
                raise AuthNeedError(request)

        # Check for permissions
        if perm:
            perms = perm.split('|')
            is_granter = False
            for p in perms:
                if request.user.has_perm(p):
                    is_granter = True
                    break
            if not is_granter:
                raise AuthNeedError(request)

    def response_success(self, response: Dict = None) -> JsonResponse:
        """
        Send response to client with status code 200(OK)

        :param response: Response to send to convert to json string.
        :return: JsonResponse
        :rtype: JsonResponse
        """

        if response is None:
            response = {}
        return JsonResponse(response, status=200)

    def response_error(self, error_message: str, is_json: bool = True, status_code: int = 500, param_name: str="") -> \
            Union[JsonResponse, HttpResponse]:
        """
        Send response to client with an error. This error can be e.g. a json or a text.

        :param error_message: Error message to send to client
        :param is_json: True if you want to response with a json
        :param status_code: Custom status code on error
        :param param_name: Parameter name if error happened on a parameter. Note: This will append to output
        when is_json is set to True
        :return: JsonResponse or HttpResponse
        :rtype: Union[JsonResponse, HttpResponse]
        """

        if is_json:
            return JsonResponse({"message": error_message, "param": param_name}, status=500)
        return HttpResponse(error_message, status=status_code)

    def response_redirect(self, address: str) -> Union[HttpResponseRedirect]:
        """
        Send redirect to user
        :param address: Address to redirect. NOTE: address is not view name!
        :return: HttpResponse
        :rtype: HttpResponseRedirect
        """
        
        return redirect(address)


class SADeleteRequest(SARequest):
    """
    Delete request
    """
    
    def auth(self) -> bool:
        """
        Authenticate user
        :return: True if current user can delete object
        :rtype: bool
        """
        raise NotImplementedError()

    @staticmethod
    def get_config(class_object: Type, key: str, encrypted: bool, field: str):
        return {"class": class_object, "key": key, "encrypted": encrypted, "field": field}
    
    def config(self) -> Dict:
        """
        Gets a Dict contains configuration of class: 
        class: Object to read data from
        key: The key name to read from post
        encrypted -> bool: If key value is encrypted by django signing. default is False
        field -> str: model filed to check key against. For example: name__iexact
        e.g. {"class": User, "key": "pk", "encrypted": True}
        :return: Dict
        :rtype: Dict
        """
        raise NotImplementedError()
    
    def post(self, request) -> HttpResponse:
        """
        Request to delete object
        :param request: HttpRequest
        :return: HttpResponse
        :rtype: HttpResponse
        """

        if not self.auth():
            return self.response_error("Permission Denied", status_code=403)
        config = self.config()

        # Check and validate config
        if not config:
            raise ValueError("Config is not correct")
        if "class" not in config:
            raise ValueError("Database model object not defined")
        if "key" not in config:
            raise ValueError("Key name is not defined")
        if "encrypted" not in config:
            config["encrypted"] = False
        if config["encrypted"]:
            item = self.get_decrypted_value(config["key"])
        if "field" not in config:
            raise ValueError("Field name is not defined")
        else:
            item = self.get_string(config["key"])
        if not item:
            return self.response_error("Item not found to delete")

        # Try to retrieve object
        object_to_delete = config["class"].objects.filter({config["field"]: item})
        try:
            object_to_delete.delete()
        except Exception:
            return self.response_error("Failed to delete item(s)")
        return self.response_success()


class RequestParamValidator(MiddlewareMixin, SARequest):

    def process_request(self, request):
        self.request = request
        request.SAR = self
