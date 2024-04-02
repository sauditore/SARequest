import codecs
import datetime
import mimetypes
import os
from decimal import Decimal
from typing import Dict, Any, List, Union, Optional, Type

from django.shortcuts import redirect, render
from pydantic import ValidationError, BaseModel, Field

from .constants import INVALID_REQUEST_METHOD, ACCESS_DENIED, API_CALLS_NOT_SUPPORTED

try:
    import khayyam
except ImportError:
    khayyam = None

from datetime import date, datetime

from uuid import uuid4, UUID

from django.contrib.auth.models import User
from django.db.models import QuerySet, Model
from django.http import HttpResponse, QueryDict, JsonResponse, HttpResponseRedirect
from django.utils.translation import gettext as _
from .manager_base import ManagerBase


class FileUploadResult(BaseModel):
    file_name: Optional[str] = Field(None)
    file_size: float = Field(0.0)
    parameter_name: Optional[str] = Field(None)
    upload_date: Optional[str] = Field(None)
    upload_path: Optional[str] = Field(None)
    user_id: Optional[int] = Field(None)


class CrudManager(ManagerBase):
    """
    Class to handle generic requests
    """

    def authorize(
            self,
            authenticate: bool = False,
            perm: str = "",
            staff: bool = False,
            superuser: bool = False) -> bool:
        """
        Validate request against referer, auth, and permissions.

        :param authenticate: Check if the user is authenticated or not.
        :param perm: Checks for a specified permission. Multi perm can be separated with a pip ( | )
        :param staff: Check if the user is staff or not. if not RequestValidationError will raise
        :param superuser: Check if the user is superuser or not. If not RequestValidationError will raise
        :return: True if the user passes validation, False otherwise

        >>>self.authorize(staff=True, perm="user.add_user|user.change_user")
        """

        if authenticate and not self.user.is_authenticated:
            return False
        if superuser and not self.user.is_superuser:
            return False
        if staff and not self.user.is_staff:
            return False

        # Check for permissions
        if perm:
            perms = perm.split('|')
            is_granter = False
            for p in perms:
                if self.user.has_perm(p):
                    is_granter = True
                    break
            if not is_granter:
                return False

        return True

    def authorize_delete(self, object_to_delete: Type) -> bool:
        """
        Authenticate user when delete is called.
        :param object_to_delete: Object that is going to delete
        :return: True if current user can delete object
        :rtype: bool

        >>>def authorize_delete(self, object_to_delete: Type) -> bool:
        >>>     return object_to_delete.user_id == self.user.pk
        The above example will only delete the record when user_id of the record is equal to the requester user id
        """
        raise NotImplementedError("No validation for delete")

    def check_perm(self) -> bool:
        """
        A logic to validate if the user can access this method and endpoint or not. This method is called
        when one of GET, POST, PUT, PATCH or DELETE requests are sent. You can overwrite this method to implement yours
        :return: True if the user can access this

        >>>def check_perm():
        >>>   return self.user.has_perm("xxx") and self.logged_in and not self.superuser
        """

        return True

    def deleted_success(self, deleted_item: Type) -> None:
        """
        When object deleted successfully then this method will call.

        :param deleted_item: deleted object
        :return: Noting returns
        """
        pass

    def delete(self, __) -> HttpResponse:
        """
        Request to delete object(s)
        :return: HttpResponse
        :rtype: HttpResponse
        """
        config = self.delete_method_configuration()

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
        else:
            item = QueryDict(self.body).get(config["key"])
        if "field" not in config:
            raise ValueError("Field name is not defined")

        if not item:
            return self.response_error("Item not found to delete")

        # Try to retrieve object
        object_to_delete = config["class"].objects.filter(**{config["field"]: item}).first()

        if not object_to_delete:
            return self.response_error("Object not found", status_code=404)

        try:
            if not self.authorize_delete(object_to_delete):
                return self.response_error(ACCESS_DENIED, status_code=403)

            object_to_delete.delete()
            self.deleted_success(object_to_delete)
        except Exception:
            return self.response_error("Failed to delete item(s)")

        return self.response_success()

    def delete_method_configuration(self) -> Dict[str, Any]:
        """
        Gets a Dict contains configuration of class:
        class: Object to read data from
        key: The key name to read from post
        encrypted -> bool: If key value is encrypted by django signing. default is False
        field -> str: model filed to check key against. For example: name__iexact
        e.g. {"class": User, "key": "pk", "encrypted": True}
        :return: Dict
        >>>return {"class": User, "key": "pk", "encrypted": True}
        note: encrypted is optional, default is False
        """
        raise NotImplementedError()

    def get(self, __, **kwargs) -> HttpResponse:
        """
        Calls when a get request is made.
        """
        if not self.check_perm():
            if self.is_api_call():
                return self.response_error(_(ACCESS_DENIED))

            else:
                return self.response_redirect("/")

        if self.is_api_call():
            return self.handle_get_api_call(**kwargs)

        return self.get_request(**kwargs)

    def handle_get_api_call(self, **kwargs) -> HttpResponse:
        """
        Calls when a get request is made with ?api_call parameter is query string.
        """
        raise NotImplementedError(API_CALLS_NOT_SUPPORTED)

    def handle_post_api_call(self, **kwargs) -> HttpResponse:
        """
        Calls when a post request is made with ?api_call in the query_string
        """
        raise NotImplementedError(API_CALLS_NOT_SUPPORTED)

    def get_request(self, **kwargs) -> HttpResponse:
        """
        The base api will call this method after validations
        """
        raise NotImplementedError(INVALID_REQUEST_METHOD)

    def patch(self, __, **kwargs) -> HttpResponse:
        """
        Calls when a patch request is made
        """
        if not self.check_perm():
            return self.response_error(_(ACCESS_DENIED))

        return self.patch_request(**kwargs)

    def patch_request(self, **kwargs) -> HttpResponse:
        """
        Calls when a patch request is made after validation
        """
        raise NotImplementedError(INVALID_REQUEST_METHOD)

    def post(self, request, **kwargs) -> HttpResponse:
        """
        Calls when a post request is made
        """
        if not self.check_perm():
            return self.response_error(_(ACCESS_DENIED))

        if self.is_api_call():
            return self.handle_post_api_call(**kwargs)

        return self.post_request(**kwargs)

    def post_request(self, **kwargs) -> HttpResponse:
        """
        Calls when a post request is made
        """
        raise NotImplementedError(INVALID_REQUEST_METHOD)

    def put(self, __, **kwargs) -> HttpResponse:
        """
        Calls when a put request is made
        """
        if not self.check_perm():
            return self.response_render(_(ACCESS_DENIED))

        return self.put_request(**kwargs)

    def put_request(self, **kwargs) -> HttpResponse:
        """
        Calls when a put request is made after validation
        """
        raise NotImplementedError(INVALID_REQUEST_METHOD)

    def is_ajax(self):
        """
        Indicates if the request is an ajax request
        """
        return self.request.META.get("HTTP_X_REQUESTED_WITH", "") == "XMLHttpRequest"

    def is_api_call(self):
        """
        Indicates if the request is needs api call or needs json response
        """
        return self.request.GET.get("api_call", "0") == "1"

    def map_to_class(self, obj: Type[BaseModel], from_body: bool = False) -> BaseModel:
        """
        Maps the request body to the given pydantic base model.
        :param obj: The model you want to map
        :param from_body: Indicates if the data should be read as str from body, Useful when making put requests
        :return: A pydantic basemodel

        >>>from pydantic import BaseModel, Field
        >>>class EditUserData(BaseModel):
        >>>     first_name: str = Field()
        >>>     last_name: str = Field()
        >>># Think a post request with these parameters are made:
        >>># firstName=name&lastName=LastName
        >>># Please be careful with the pascal case of the parameters
        >>>user_data = self.map_to_class(EditUserData)

        There are some limitations like file uploads. But with normal fields works perfectly.
        If you define request_user_id in your pydantic model, then the mapper will add user id to it automatically
        """
        to_map = {}
        schema = obj.schema()["properties"]

        if from_body:
            items = self.json().items()
        else:
            items = self.store.items()

        for key, value in items:
            normal_key = self._normalize_key_name(key)
            if value == "":
                to_map[normal_key] = None
            else:
                if normal_key in schema and schema[normal_key]["type"] == "array":
                    to_map[normal_key] = self.store.getlist(key)
                else:
                    to_map[normal_key] = value

        if "request_user_id" in schema:
            user_id = 0
            if self.logged_in:
                user_id = self.user.pk

            to_map["request_user_id"] = user_id

        return obj(**to_map)

    def response_render(self, template_path: str, context: Optional[Dict] = None) -> HttpResponse:
        """
        Return rendered HTML

        :param template_path: path of html
        :param context: context data
        :return: Rendered HTML
        :rtype: HttpResponse
        """

        return render(self.request, template_path, context=context)

    def handle_upload(
            self,
            base_path: str,
            add_date: bool = False,
            add_user: bool = False,
            random_name: bool = False) -> List[FileUploadResult]:
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
        today = date.today().strftime("%Y%m%d")
        if add_date:
            today_path = os.path.join(base_path, today)
            if not os.path.exists(today_path):
                os.mkdir(today_path)
        else:
            today_path = base_path
        if add_user:
            if not self.request.user.is_authenticated:
                # if user is not authenticated, then use ALL as the name
                user_path = os.path.join(today_path, "ALL")
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
                file_list = self.request.FILES.getlist(f)
                for file in file_list:
                    if random_name:
                        t = os.path.join(user_path, str(uuid4()))
                    else:
                        t = os.path.join(user_path, str(file))
                    a = codecs.open(t, "w+b")
                    for d in file:
                        a.write(d)
                    a.close()
                    file_size = os.stat(t).st_size
                    uid = self.request.user.pk if self.logged_in else 0

                    res.append(FileUploadResult(
                        file_name=str(file),
                        file_size=file_size,
                        parameter_name=f,
                        upload_date=today,
                        upload_path=t,
                        user_id=uid
                    ))
            except Exception:
                continue
        return res

    def respond_as_attachment(self, file_path: str, original_filename: str) -> HttpResponse:
        """
        Response file to user. This method is good for small chunks of file.

        :param file_path: File path to read
        :param original_filename:  Original name of the file
        :return: HttpResponse
        """

        if original_filename is None:
            original_filename = "unknown_file"

        fp = open(str(file_path), "rb")
        response = HttpResponse(fp.read())
        fp.close()
        f_type, encoding = mimetypes.guess_type(original_filename)
        if f_type is None:
            f_type = "application/octet-stream"
        response["Content-Type"] = f_type
        response["Content-Length"] = str(os.stat(file_path.encode("utf-8")).st_size)
        if encoding is not None:
            response["Content-Encoding"] = encoding

        # To inspect details for the below code, see http://greenbytes.de/tech/tc2231/
        if "WebKit" in self.request.META["HTTP_USER_AGENT"]:
            # Safari 3.0 and Chrome 2.0 accepts UTF-8 encoded string directly.
            filename_header = f'filename={original_filename}'

        elif "MSIE" in self.request.META["HTTP_USER_AGENT"]:
            # IE does not support internationalized filename at all.
            # It can only recognize internationalized URL, so we do the trick via routing rules.
            filename_header = ""
        else:
            # For others like Firefox, we follow RFC2231 (encoding extension in HTTP headers).
            filename_header = f"filename*=UTF-8\'\'{original_filename}"
        response["Content-Disposition"] = f"attachment; {filename_header}"
        return response

    @staticmethod
    def response_success(response: Dict = None) -> JsonResponse:
        """
        Send response to client with status code 200(OK)

        :param response: Response to send to convert to json string.
        :return: JsonResponse
        """

        def default_parser(data):
            if isinstance(data, datetime):
                return data.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(data, date):
                return data.strftime("%Y-%m-%d")

            elif isinstance(data, Decimal):
                return float(data)
            elif isinstance(data, UUID):
                return str(data)

        if response is None:
            response = {}
        return JsonResponse(response, status=200, json_dumps_params={"default": default_parser})

    @staticmethod
    def response_not_found(error_message: str, param_name: str = "") -> JsonResponse:
        """
        Send error_message to user as a json response with status code 404(not found)

        :param error_message: Error message to show to user
        :param param_name: parameter name that was not exist
        :return: JsonResponse
        """

        return JsonResponse({"message": error_message, "param": param_name}, status=404)

    @staticmethod
    def response_error(error_message: str, is_json: bool = True, status_code: int = 500, param_name: str = "") -> \
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

    @staticmethod
    def validation_error_response(validation_error: ValidationError):
        """
        Parse and send validation error response. This response type usually generated by pydantic
        :param validation_error: Validation error to parse.

        """

        return HttpResponse(validation_error.json(), status=409, content_type="text/json")

    @staticmethod
    def response_redirect(address: str) -> Union[HttpResponseRedirect]:
        """
        Send redirect to user
        :param address: Address to redirect. NOTE: address is not view name!
        :return: HttpResponse
        :rtype: HttpResponseRedirect
        """

        return redirect(address)

    def sort_by(self, model: Model, query_set: QuerySet, parameter_name: str = "sort") -> QuerySet:
        """
        Sort the query set by the given field in the request
        :param model: The Django model
        :param query_set: The queryset to be sorted
        :param parameter_name: The name of the `sort` parameter to read from request
        """

        field_name = self.get_string("sort", default="")
        if not field_name:
            return query_set

        real_field_name = field_name
        options = model._meta

        fields: List[str] = []
        for field in sorted(options.concrete_fields + options.many_to_many):
            fields.append(field.name)

        if field_name.startswith("-"):
            if len(field_name) < 2:
                return query_set

            real_field_name = field_name[1:]

        if real_field_name not in fields:
            return query_set

        return query_set.order_by(field_name)

    @staticmethod
    def get_config(class_object: Type, key: str = "pk", encrypted: bool = False, field: str = "pk"):
        return {"class": class_object, "key": key, "encrypted": encrypted, "field": field}

    @staticmethod
    def _normalize_key_name(key: str) -> str:
        final_key: str = ""
        for c in key:
            if c.isupper():
                final_key += f"_{c.lower()}"
            else:
                final_key += c
        return final_key
