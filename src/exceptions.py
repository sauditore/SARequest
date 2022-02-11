import os
from typing import Tuple

from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext as _


class RequestProcessingErrorBase(Exception):
    """
    Base class for process errors
    """

    def __init__(self, msg: str, args: Tuple, param: str, status_code: int):
        """
        init
        :param msg: Error Message
        :param args: Exception args
        :param param: Parameter name
        :param status_code: HTTP status code
        """

        self.message = msg
        self.args = args
        self.param = param
        self.status = status_code

    def get_json_response(self) -> JsonResponse:
        """
        Returns json response to send to client.
        :return: JsonResponse
        """

        return JsonResponse({"message": self.message, "param": self.param, "status": self.status})


class ParamNotFoundError(RequestProcessingErrorBase):
    """
    When a parameter is absent this will raise
    """

    def __init__(self, msg, param=""):
        super(ParamNotFoundError, self).__init__(msg, (msg, ), param, 404)


class ValueOutOfRangeError(RequestProcessingErrorBase):
    """
    The value is out of range of min or max
    """

    def __init__(self, name, min_value, max_value):
        super(ValueOutOfRangeError, self).__init__("Value is not in range", ("Min Value: ",
                                                                             min_value,
                                                                             " - Max Value: ",
                                                                             max_value), name, 500)


class RequestValidationError(RequestProcessingErrorBase):
    """
    Occurs when user request validation failed.  For example, you need POST request and user sent a
    GET request
    """

    def __init__(self, message, args):
        self.message = message
        self.args = args
        super(RequestValidationError, self).__init__(message, args, "", 401)


class InvalidParamFormatError(RequestProcessingErrorBase):
    """
    Class to handle invalid param format
    """

    def __init__(self, name, valid_example):
        super(InvalidParamFormatError, self).__init__(_("Parameter format is not correct."),
                                                      (valid_example,), name, 500)


class AuthNeedError(RequestProcessingErrorBase):
    """
    Occurs when user is not logged-in or permission is not enough
    """

    def __init__(self, request):
        """
        Occurs when user is not logged-in or permission is not enough
        :param request: Django request
        """
        self.request = request
        super(AuthNeedError, self).__init__("Use must login to view this resource", (), "", 401)

    def get_response(self):
        self.request.session['return_login_address'] = self.request.get_full_path()
        return redirect(reverse('auth_login'))


class ObjectNotFoundError(RequestProcessingErrorBase):
    """
    Occurs when a db object must read but it's not exists.
    """

    def __init__(self, name):
        super(ObjectNotFoundError, self).__init__(_("Data you are looking for is not exists."), (), name, 404)


class RangeFileWrapper(object):
    def __init__(self, filelike, blksize=1024, offset=0, length=None):
        self.filelike = filelike
        self.filelike.seek(offset, os.SEEK_SET)
        self.remaining = length
        self.blksize = blksize

    def close(self):
        if hasattr(self.filelike, 'close'):
            self.filelike.close()

    def __iter__(self):
        return self

    def next(self):
        if self.remaining is None:
            # If remaining is None, we're reading the entire file.
            data = self.filelike.read(self.blksize)
            if data:
                return data
            raise StopIteration()
        else:
            if self.remaining <= 0:
                raise StopIteration()
            data = self.filelike.read(min(self.remaining, self.blksize))
            if not data:
                raise StopIteration()
            self.remaining -= len(data)
            return data