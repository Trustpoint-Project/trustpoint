# Trustpoint View Design Guidelines

This document defines how views in the Trustpoint web interface should be structured and designed.

The goal is to provide a consistent user experience across all Trustpoint modules while keeping the frontend maintainable and based on the existing Trustpoint and Bootstrap components.

These guidelines apply to:

- management views
- PKI views
- device and agent management
- certificate lifecycle management
- signer management
- network discovery
- workflow management
- configuration pages
- import and export pages
- confirmation dialogs
- new Trustpoint modules

Specialized interfaces such as the Setup Wizard or graphical workflow editors may use additional components where required by their functionality.

---

# 1. General Design Principles

Trustpoint is an enterprise application for PKI, certificate lifecycle management, device onboarding, and industrial cybersecurity.

Views should therefore be:

- clear
- technical
- predictable
- compact
- accessible
- suitable for large amounts of structured information
- usable in both light and dark mode

The general principle is:

> **Text first, color only for meaningful state, and icons only where they add real information.**

Avoid decorative elements that do not help the user understand or operate the system.

---

# 2. Use Existing Trustpoint and Bootstrap Components

New views should primarily use:

- Bootstrap
- existing Trustpoint CSS classes
- existing Trustpoint partials
- Django templates
- existing JavaScript utilities

Do not introduce a new frontend framework for individual views.

Prefer standard components such as:

```html
.card
.card-header
.card-body
.card-footer

.btn
.btn-primary
.btn-secondary
.btn-outline-secondary
.btn-danger
.btn-outline-danger

.table
.table-hover
.table-responsive

.alert
.badge

.form-control
.form-select
.form-check
```

Trustpoint-specific components such as the following should be reused where appropriate:

```html
.tp-card-centered-content
.tp-kvp-list
.tp-status-badge
.tp-status-dot
.tp-table-select-btn
```

---

# 3. Standard Page Structure

Most Trustpoint pages should consist of one main card.

Recommended structure:

```django
<div class="card">
    <div class="card-header">
        <h1 class="mb-1">
            {% trans "Page Title" %}
        </h1>

        <p class="mb-0 text-muted">
            {% trans "Short description of the purpose of this page." %}
        </p>
    </div>

    <div class="card-body text-start">
        ...
    </div>

    <div class="card-footer">
        ...
    </div>
</div>
```

Avoid wrapping the entire page in several nested cards unless the contained elements are genuinely independent modules.

---

# 4. Page Titles

Every page should have one `<h1>`.

Example:

```django
<h1 class="mb-1">
    {% trans "Certificate Authorities" %}
</h1>
```

A short description should normally follow:

```django
<p class="mb-0 text-muted">
    {% trans "Manage the certificate authorities available in Trustpoint." %}
</p>
```

Avoid redundant headings such as:

```text
Add New Signer
Create Signer
Signer Creation
```

on the same page.

Once a workflow step is selected, the page title should describe the current task directly.

Prefer:

```text
Generate Signer
```

instead of:

```text
Add New Signer - Generate With Crypto Backend
```

---

# 5. Page Sections

Major areas within a page should use semantic `<section>` elements.

Recommended pattern:

```django
<section class="mb-5">
    <div class="mb-3">
        <h2 class="h4 mb-1">
            {% trans "General" %}
        </h2>

        <p class="mb-0 text-muted">
            {% trans "General configuration for this object." %}
        </p>
    </div>

    <hr class="mb-4">

    ...
</section>
```

The final section normally does not require `mb-5`.

Use a consistent heading hierarchy:

- `h1` — page
- `h2` — major section
- `h3` — subsection
- `h4` and below — only when required

---

# 6. Forms

Forms should normally exist only around the inputs that actually belong to the form.

Avoid:

```django
<form>
    <div class="card">
        ...
    </div>
</form>
```

Prefer:

```django
<div class="card">
    <div class="card-body">
        <form id="device-form" method="post">
            ...
        </form>
    </div>

    <div class="card-footer">
        <button
            type="submit"
            form="device-form"
            class="btn btn-primary"
        >
            {% trans "Save" %}
        </button>
    </div>
</div>
```

Use specific form IDs such as:

```html
id="create-device-form"
id="import-signer-form"
id="domain-configuration-form"
```

Avoid generic IDs such as:

```html
id="form"
id="main-form"
```

---

# 7. Centered Forms

Narrow configuration forms may use:

```html
<div class="tp-card-centered-content">
```

Do not use this layout for large inventories, dashboards, or wide technical tables.

---

# 8. Form Actions

The normal footer structure for forms is:

```django
<div class="card-footer d-flex justify-content-between align-items-center">
    <a
        href="..."
        class="btn btn-secondary"
    >
        {% trans "Cancel" %}
    </a>

    <button
        type="submit"
        form="example-form"
        class="btn btn-primary"
    >
        {% trans "Save Changes" %}
    </button>
</div>
```

For workflows with both Back and Cancel:

```django
<div class="card-footer d-flex justify-content-between align-items-center">
    <div class="d-flex gap-2">
        <a href="..." class="btn btn-secondary">
            {% trans "Back" %}
        </a>

        <a href="..." class="btn btn-outline-secondary">
            {% trans "Cancel" %}
        </a>
    </div>

    <button class="btn btn-primary">
        {% trans "Continue" %}
    </button>
</div>
```

---

# 9. Button Hierarchy

## Primary action

Use:

```html
btn btn-primary
```

Examples:

- Create Device
- Add Domain
- Save Changes
- Import Signer
- Generate Signer
- Apply and Continue

A page should normally have only one visually dominant primary action.

## Secondary actions

Use:

```html
btn btn-secondary
```

or:

```html
btn btn-outline-secondary
```

Examples:

- Back
- Cancel
- Configure
- Details
- Download
- Signing Log
- View Certificates
- Export

## Destructive actions

Use:

```html
btn btn-danger
```

for final destructive confirmation.

Use:

```html
btn btn-outline-danger
```

for destructive actions on inventory or detail pages.

---

# 10. Action Labels

Use explicit action text.

Prefer:

```text
Edit
Delete
Details
Download
Configure
Back
Cancel
```

Avoid icon-only controls for ordinary operations.

Icons may still be used where they provide meaningful supplemental information.

---

# 11. Inventory Tables

Standard Trustpoint inventory tables should use:

```django
<div class="table-responsive">
    <table class="table table-hover align-middle">
        ...
    </table>
</div>
```

Do not create a second vertical scrollbar around normal tables.

The page should use the browser's natural vertical scrolling.

---

# 12. Pagination

Responsive tables and pagination are independent.

Recommended structure:

```django
<div class="table-responsive">
    <table class="table table-hover align-middle">
        ...
    </table>
</div>

{% include "trustpoint/pagination.html" %}
```

`table-responsive` only enables horizontal scrolling where required.

It does not replace or disable server-side pagination.

---

# 13. Table Actions

Use one **Actions** column.

Actions should normally use neutral text buttons:

```django
<td class="text-end">
    <a
        href="..."
        class="btn btn-sm btn-outline-secondary"
    >
        {% trans "Details" %}
    </a>
</td>
```

Avoid `btn-primary` for every action in every row.

---

# 14. Empty Tables

Use a clear, neutral empty state.

```django
<tr>
    <td
        colspan="6"
        class="text-center text-muted py-5"
    >
        {% trans "No devices have been configured yet." %}
    </td>
</tr>
```

Always update `colspan` if table columns change.

---

# 15. Missing Values

Use an em dash:

```text
—
```

Example:

```django
{% if device.serial_number %}
    {{ device.serial_number }}
{% else %}
    <span class="text-muted">—</span>
{% endif %}
```

---

# 16. Status Information

Color should primarily communicate meaningful state.

Appropriate examples:

```django
<span class="badge text-bg-success">
    {% trans "Active" %}
</span>

<span class="badge text-bg-warning">
    {% trans "Expiring Soon" %}
</span>

<span class="badge text-bg-danger">
    {% trans "Expired" %}
</span>

<span class="badge text-bg-secondary">
    {% trans "Disabled" %}
</span>
```

Trustpoint status components may also be used:

```django
<span class="tp-status-badge tp-status-{{ status.status_key }}">
    <span class="tp-status-dot"></span>
    {{ status.status_label }}
</span>
```

---

# 17. Filters

Filters should normally be presented as a compact dropdown above the table.

Typical order:

```text
Filters | Columns | Export
```

Recommended layout:

```django
<div class="d-flex flex-wrap gap-2 align-items-center">
    <div class="dropdown">
        ...
    </div>

    <div class="dropdown">
        ...
    </div>

    <a class="btn btn-sm btn-outline-secondary">
        {% trans "Export" %}
    </a>
</div>
```

---

# 18. Filter Button

Recommended filter button:

```django
<button
    class="btn btn-sm {% if filters_active %}btn-primary{% else %}btn-outline-secondary{% endif %} dropdown-toggle"
    type="button"
    data-bs-toggle="dropdown"
    data-bs-auto-close="outside"
    aria-expanded="false"
>
    {% trans "Filters" %}

    {% if filters_active %}
        <span class="ms-1">
            · {% trans "Active" %}
        </span>
    {% endif %}
</button>
```

Do not use `aria-expanded="true"` merely because filters are active.

---

# 19. Filter Form Footer

Recommended:

```django
<div class="d-flex justify-content-between gap-2">
    <a
        href="..."
        class="btn btn-sm btn-outline-secondary"
    >
        {% trans "Reset" %}
    </a>

    <button
        type="submit"
        class="btn btn-sm btn-primary"
    >
        {% trans "Apply Filters" %}
    </button>
</div>
```

---

# 20. Column Visibility

Large technical tables may provide a Columns dropdown.

Do not rename existing `data-col` values without also updating the associated JavaScript.

---

# 21. Sorting

Sortable table headers should remain visually subtle.

```django
<a
    href="?sort=name"
    class="text-decoration-none text-body"
>
    {% trans "Name" %}
</a>
```

---

# 22. Selection Pages

Views that select between workflows may use cards.

Examples:

- Generate vs Import
- PKCS#12 vs Separate Files
- EST vs CMP
- IDevID vs AOKI
- Onboarding vs No Onboarding

Descriptions should explain differences that matter to the user.

If the choices are already self-explanatory, avoid unnecessary repetitive text.

---

# 23. Detail Pages

Detail pages should usually use sections and `tp-kvp-list`.

```django
<section class="mb-5">
    <h2 class="h4 mb-1">
        {% trans "General" %}
    </h2>

    <hr class="mb-4">

    <div class="tp-kvp-list">
        <div>
            <div>{% trans "Name" %}</div>
            <div>{{ object.name }}</div>
        </div>

        <div>
            <div>{% trans "Created" %}</div>
            <div>{{ object.created_at|local_datetime }}</div>
        </div>
    </div>
</section>
```

Do not create a separate nested card for every section.

---

# 24. Technical Values

Technical identifiers should generally use monospace.

Suitable values include:

- serial numbers
- hashes
- fingerprints
- signatures
- key identifiers
- URIs where appropriate
- certificate identifiers

Long values may additionally use `text-break`.

---

# 25. Copy-to-Clipboard

Copy controls are appropriate for technical values such as:

- signatures
- hashes
- certificate fingerprints
- commands
- tokens intended for explicit copying

Copy icons are meaningful technical controls and are therefore an acceptable use of icons.

---

# 26. Modals

Use modals only when they improve the workflow.

Good use cases:

- inspecting a full cryptographic signature
- displaying PEM data
- examining long technical content without navigating away

Do not move ordinary page information into modals merely to reduce page length.

---

# 27. Confirmation and Deletion Pages

Destructive operations should use a dedicated confirmation page.

```django
<div class="alert alert-warning" role="alert">
    <strong>
        {% trans "The selected objects will be permanently deleted." %}
    </strong>

    <div class="mt-1">
        {% trans "This action cannot be undone." %}
    </div>
</div>
```

The final action should use `btn btn-danger`.

If an association is removed but the underlying object remains, use wording such as `Remove Selected` rather than `Delete Selected`.

---

# 28. Alerts

Alerts should communicate meaningful information.

Use them for:

- warnings
- validation errors
- important system state
- security implications
- successful completion
- configuration state requiring attention

Do not use alerts merely as decorative information containers.

---

# 29. Dashboard Metrics

Dashboard-style pages may use small nested cards for metrics.

Metrics should normally remain visually neutral.

Avoid using different colors for each metric unless the color itself communicates a meaningful state.

---

# 30. Scrolling

Trustpoint should generally use normal browser page scrolling.

Avoid:

```html
style="height: calc(100vh - ...)"
style="max-height: 90%"
style="overflow-y: auto"
style="flex-grow: 1"
```

on normal page content.

Avoid nested vertical scroll areas.

For tables, use `table-responsive` to handle horizontal overflow.

Dedicated technical viewers, such as log or PEM viewers, may have their own scrolling region where necessary.

---

# 31. Sticky Footers

Normal application cards should not require custom sticky footers.

Avoid:

```html
tp-sticky-footer
```

unless there is a clear functional reason.

Use normal page flow.

---

# 32. Light and Dark Mode

Views must work in both supported themes.

Avoid hardcoded colors such as:

```css
background: white;
color: black;
background: #fff;
```

Prefer Bootstrap theme variables and semantic classes.

Custom CSS should use Bootstrap variables where appropriate:

```css
color: var(--bs-body-color);
background-color: var(--bs-body-bg);
border-color: var(--bs-border-color);
```

---

# 33. Internationalization

All new user-visible text must use Django internationalization.

Use:

```django
{% trans "Save Changes" %}
```

or:

```django
{% blocktrans with name=device.common_name %}
    Configure device {{ name }}.
{% endblocktrans %}
```

---

# 34. Accessibility

Views should use semantic HTML and meaningful labels.

Examples:

```html
<th scope="col">
```

```django
<label for="{{ form.device.id_for_label }}">
```

```django
<input
    type="checkbox"
    aria-label="{% trans 'Select all devices' %}"
>
```

Icon-only controls require an accessible label.

Decorative icons should use:

```html
aria-hidden="true"
```

---

# 35. Preserve Existing Functionality

Frontend redesigns must not change backend behavior unless the change is intentional and reviewed separately.

When redesigning an existing template, preserve:

- URL names
- URL parameters
- form field names
- POST actions
- form IDs used by JavaScript
- element IDs used by JavaScript
- `data-*` attributes
- permissions
- Django template conditions
- CSRF handling
- button `name` and `value` attributes
- file upload encoding
- JavaScript hooks

Do not remove:

```html
enctype="multipart/form-data"
```

from file upload forms.

---

# 36. GET vs POST

Do not use a form when the page only contains navigation links.

Use POST only for actions that modify state.

---

# 37. Specialized Views

Some Trustpoint views require specialized components.

Examples include:

- Setup Wizard
- Workflow Editor
- graph editors
- code editors
- log viewers
- interactive certificate viewers

These views may retain feature-specific CSS and JavaScript.

However, their surrounding interaction patterns should still follow the Trustpoint conventions where possible:

- standard action hierarchy
- semantic headings
- internationalization
- accessible controls
- theme compatibility
- neutral ordinary actions
- state-based color usage

Feature-specific CSS should not be introduced merely to recreate functionality already available through standard Bootstrap or Trustpoint components.

---

# 38. Recommended Inventory Page Template

```django
{% extends "trustpoint/base.html" %}
{% load i18n %}

{% block content %}
<div class="card">
    <div class="card-header">
        <h1 class="mb-1">
            {% trans "Objects" %}
        </h1>

        <p class="mb-0 text-muted">
            {% trans "Manage objects available in Trustpoint." %}
        </p>
    </div>

    <div class="card-body text-start">
        <section>
            <div class="mb-3">
                <h2 class="h4 mb-1">
                    {% trans "Object Inventory" %}
                </h2>
            </div>

            <hr class="mb-4">

            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    ...
                </table>
            </div>

            {% include "trustpoint/pagination.html" %}
        </section>
    </div>

    <div class="card-footer d-flex justify-content-between align-items-center">
        <button
            type="button"
            class="btn btn-outline-danger tp-table-select-btn"
        >
            {% trans "Delete Selected" %}
        </button>

        <a
            href="..."
            class="btn btn-primary"
        >
            {% trans "Create Object" %}
        </a>
    </div>
</div>
{% endblock content %}
```

---

# 39. Recommended Form Page Template

```django
{% extends "trustpoint/base.html" %}
{% load i18n %}
{% load crispy_forms_filters %}

{% block content %}
<div class="card">
    <div class="card-header">
        <h1 class="mb-1">
            {% trans "Configure Object" %}
        </h1>

        <p class="mb-0 text-muted">
            {% trans "Configure the settings for this object." %}
        </p>
    </div>

    <div class="card-body text-start">
        <div class="tp-card-centered-content">
            <form
                id="object-form"
                method="post"
                autocomplete="off"
            >
                {% csrf_token %}

                <section>
                    <div class="mb-3">
                        <h2 class="h4 mb-1">
                            {% trans "General" %}
                        </h2>
                    </div>

                    <hr class="mb-4">

                    {{ form|crispy }}
                </section>
            </form>
        </div>
    </div>

    <div class="card-footer d-flex justify-content-between align-items-center">
        <a href="..." class="btn btn-secondary">
            {% trans "Cancel" %}
        </a>

        <button
            type="submit"
            form="object-form"
            class="btn btn-primary"
        >
            {% trans "Save Changes" %}
        </button>
    </div>
</div>
{% endblock content %}
```

---

# 40. Review Checklist

Before merging a new or redesigned view, verify the following.

## Structure

- [ ] The page has one clear `<h1>`.
- [ ] Major areas use semantic sections.
- [ ] Unnecessary nested cards have been avoided.
- [ ] Normal page scrolling is used.
- [ ] No unnecessary fixed viewport height exists.

## Actions

- [ ] There is normally only one primary page action.
- [ ] Ordinary row actions use neutral styling.
- [ ] Destructive actions use danger semantics.
- [ ] Buttons use explicit text labels.

## Tables

- [ ] Tables use `table-responsive`.
- [ ] Tables use `table table-hover align-middle`.
- [ ] There is one Actions column.
- [ ] Empty states are clear.
- [ ] Missing values use `—`.
- [ ] Pagination remains outside the responsive table wrapper.

## Forms

- [ ] Forms have a specific ID.
- [ ] Footer submit buttons use the form ID.
- [ ] CSRF is present for POST forms.
- [ ] File upload forms retain `multipart/form-data`.
- [ ] Back, Cancel, and primary actions are clearly separated.

## Status

- [ ] Color is used only when it communicates state or severity.
- [ ] Status badges use semantic colors.
- [ ] Ordinary values do not use arbitrary colors.

## Compatibility

- [ ] Light mode works.
- [ ] Dark mode works.
- [ ] No hardcoded white/black backgrounds were introduced.
- [ ] Mobile layouts remain usable.

## Accessibility

- [ ] Form fields have labels.
- [ ] Table headers use appropriate semantics.
- [ ] Checkbox controls have accessible labels.
- [ ] Icon-only controls have an `aria-label`.
- [ ] Decorative icons use `aria-hidden="true"`.

## Internationalization

- [ ] All new visible text uses `{% trans %}` or `{% blocktrans %}`.

## Functional Preservation

- [ ] Existing URLs are unchanged.
- [ ] Existing form field names are unchanged.
- [ ] Existing JavaScript IDs and `data-*` hooks are unchanged.
- [ ] Existing permission checks are unchanged.
- [ ] Existing template conditions are unchanged.

---

# 41. Core Rule

When designing a Trustpoint view, prefer the simplest standard component that communicates the required information.

A new page should look and behave like part of Trustpoint without requiring the user to learn a new interaction pattern for each module.
