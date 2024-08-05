# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os
import requests
import json
from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache
from flask import redirect, g, request, flash
from werkzeug.security import check_password_hash
from superset.security.manager import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_login import login_user
from flask_appbuilder.security.views import AuthRemoteUserView
from flask_appbuilder import expose
from superset import app, db

logger = logging.getLogger()

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

EXAMPLES_USER = os.getenv("EXAMPLES_USER")
EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SQLALCHEMY_EXAMPLES_URI = (
    f"{DATABASE_DIALECT}://"
    f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
    f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG


class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = ("superset.sql_lab",)
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }


CELERY_CONFIG = CeleryConfig

class RemoteUserMiddleware(object):
        def __init__(self, app):
            self.app = app
        def __call__(self, environ, start_response):
            user = environ.pop('HTTP_USER', None)
            environ['REMOTE_USER'] = user
    
            return self.app(environ, start_response)
    
ADDITIONAL_MIDDLEWARE = [RemoteUserMiddleware]
    
class CustomRemoteUserView(AuthRemoteUserView):
    login_template = ""
    
    @expose("/login/")
    def login(self):
        logger.info("Using custom security manager")
        username = ""
        token = request.args.get('token')
        tenant_identifier = request.args.get('id')
        tenant_code = request.args.get('code')
        url = "https://gateway.uat.fortecloud.io/api/v1/profile"

        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        def get_userName(user_roles):
            report_admin_present =  any(role.get('roleName') == 'REPORT_ADMIN' for role in user_roles)
            if report_admin_present:
                return tenant_code + "_reportadmin"
            
            report_view_present = any(role.get('roleName') == 'REPORT_VIEW' for role in user_roles)
            if report_view_present:
                return tenant_code + "_reportviewer"

        try:
            token = "Bearer " + token
            response = requests.get(url, headers={"Tenant_identifier":tenant_identifier, "Authorization": token})

            if response.status_code == 200:
                user_data = response.json()
                user_roles = user_data['data']['userRoles']
                logger.info("userprofile")

                logger.info(user_roles)
                security_manager = self.appbuilder.sm
                username=get_userName(user_roles)

                logger.info(username)

                user_model = security_manager.user_model
                role_model = security_manager.role_model

                # user = db.session.query(user_model).filter_by(username=username).one()
                user = security_manager.find_user(username=username)
                admin_role = security_manager.find_role("Admin")
                # admin_role = db.session.query(role_model).filter_by(name='Admin').one()

                with app.app_context():
                    logger.info("Records from db")
                    logger.info(admin_role)
                    logger.info("user_security")
                    # logger.info(user_security)
                    # logger.info(admin_role_security)
                    logger.info("details")
                    if user is not None:
                        user.roles.append(admin_role)
                        logger.info(user)
                        logger.info(user.roles)
                        db.session.commit()
                        login_user(user)
                        return redirect(self.appbuilder.get_url_for_index)
                    else:
                        print('Error:', response.status_code)
                        logger.warning("User not found")
                        return redirect('/login/')
        except requests.exceptions.RequestException as e:
            logger.error('Error:')
            return redirect('/login/')
class CustomSecurityManager(SupersetSecurityManager):
    authremoteuserview = CustomRemoteUserView

CUSTOM_SECURITY_MANAGER = CustomSecurityManager
AUTH_TYPE = AUTH_REMOTE_USER

FEATURE_FLAGS = {"ALERT_REPORTS": True}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
SQLLAB_CTAS_NO_LIMIT = True

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker
    from superset_config_docker import *  # noqa

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")
