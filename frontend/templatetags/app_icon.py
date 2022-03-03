from django import template
from server.settings import WAPP_ICON

register = template.Library()


@register.filter
def app_icon(product):
    html = '''<span class="badge badge-diy badge-pill">{}</span>'''.format(
        product)
    if product in WAPP_ICON:
        try:
            icon = WAPP_ICON[product]["icon"]
            path = "/static/images/icons/" + icon
            html = '''<img src="{}" class="img-ss" alt="{}" title="{}">'''.format(
                path, product, product)
        except KeyError:
            pass
    return html
