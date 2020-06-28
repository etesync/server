from django.conf import settings
from django.conf.urls import include
from django.urls import path

from rest_framework_nested import routers

from django_etebase import views

router = routers.DefaultRouter()
router.register(r'collection', views.CollectionViewSet)
router.register(r'authentication', views.AuthenticationViewSet, basename='authentication')
router.register(r'invitation/incoming', views.InvitationIncomingViewSet, basename='invitation_incoming')
router.register(r'invitation/outgoing', views.InvitationOutgoingViewSet, basename='invitation_outgoing')

collections_router = routers.NestedSimpleRouter(router, r'collection', lookup='collection')
collections_router.register(r'item', views.CollectionItemViewSet, basename='collection_item')
collections_router.register(r'member', views.CollectionMemberViewSet, basename='collection_member')

item_router = routers.NestedSimpleRouter(collections_router, r'item', lookup='collection_item')
item_router.register(r'chunk', views.CollectionItemChunkViewSet, basename='collection_items_chunk')

if settings.DEBUG:
    router.register(r'test/authentication', views.TestAuthenticationViewSet, basename='test_authentication')

app_name = 'django_etebase'
urlpatterns = [
    path('v1/', include(router.urls)),
    path('v1/', include(collections_router.urls)),
    path('v1/', include(item_router.urls)),
]
