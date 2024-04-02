from __future__ import annotations
from typing import Type, Dict, Any

from django.db.models import Model
from django.http import HttpResponse
from pydantic import BaseModel, ValidationError

from django_crud_manager import ActionResult
from django_crud_manager.manager import CrudManager


class GeneralCrudManager(CrudManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.request_kwargs = {}

    @property
    def base_db_class(self) -> Type[Model]:
        raise NotImplementedError("Need to define the DB Model")

    def config(self) -> Dict[str, Any]:
        return self.get_config(self.base_db_class)

    @property
    def template(self) -> (str, str):
        raise NotImplementedError("Need to return the template name")

    @property
    def request_model(self) -> Type[BaseModel]:
        raise NotImplementedError("Need to define the request model")

    def validate_post_data(self, data) -> ActionResult:
        return ActionResult.success()

    def clear_post_data(self, data):
        return data.dict()

    def post_action_completed(self, data):
        pass

    @property
    def template_extra_context(self) -> Dict[str, Any]:
        return {}

    def get_request(self, **kwargs) -> HttpResponse:
        self.request_kwargs = kwargs
        data = self.search(**kwargs)
        template_address, data_name = self.template
        paged = self.paginate(data, data_name, self.template_extra_context)
        return self.response_render(template_address, paged)

    def post_request(self, **kwargs) -> HttpResponse:
        try:
            mapped_data = self.map_to_class(self.request_model)
        except ValidationError as e:
            return self.validation_error_response(e)

        self.request_kwargs = kwargs
        validation_result = self.validate_post_data(mapped_data)

        if validation_result.is_success:
            clear_data = self.clear_post_data(mapped_data)
            new_object = self.base_db_class.create(**clear_data)
            self.post_action_completed(new_object)
            return self.response_success()

        return self.response_error(validation_result.message)

    def search(self, **kwargs):
        return self.base_db_class.objects.filter()

    @property
    def validate_data_request(self):
        return self.request.GET.get("isValidation") == "1"
