# -*- coding: utf-8 -*-

{
    'name': 'JWT Authentication',
    'description': 'JWT Authentication with odoo controllers',
    'version': '1.0',
    'author': 'samiakram@live.com',
    'license': 'AGPL-3',
    'category': 'Authentication',
    'data': [
        'security/groups.xml',
        'security/ir.model.access.csv',
        'views/login.xml',
        'views/api_test.xml',
    ],
    "assets": {
    },
    'images': [
        'static/description/main_screenshot.png',
    ],
    'post_init_hook': '_install_jwt',
    'depends': ['base'],
    'application': True
}
