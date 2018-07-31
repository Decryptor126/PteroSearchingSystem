# !/usr/bin/env python3
# -*- coding: utf-8 -*-

#防跨站请求伪造
#TODO: 为增强安全性，密钥不应该直接写入代码，而应该保存在环境变量当中
class Config(object):
    CSRF_ENABLED = True
    SECRET_KEY = '736670cb10a600b695a55839ca3a5aa54a7d7356cdef815d2ad6e19a2031182b'
    
class ProdConfig(Config):
    pass
    
class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///database.db"
    