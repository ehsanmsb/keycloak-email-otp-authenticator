<#import "template.ftl" as layout>
<@layout.emailLayout>
<#if emailIntroText?? && emailIntroText?has_content>
<p>${kcSanitize(emailIntroText)?no_esc}</p>
</#if>
${kcSanitize(msg("emailCodeBodyHtml", code, ttl))?no_esc}
</@layout.emailLayout>
