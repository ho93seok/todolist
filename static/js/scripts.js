// When the whole page has loaded, including all dependent resources such as stylesheets, scripts, iframes, and images...
window.addEventListener( "load", (event) =>{

    // Get the #create_task_due_date form field
    var dateField = document.getElementById( 'create_task_due_date' );

    // If the #due_dute form field is present...
    if( dateField ){

        // Set the default value to today.
        dateField.valueAsDate = new Date();
    }

});
