﻿#pragma checksum "..\..\EditRule.xaml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "28030313B7A6B59A0E6AC519BC7081FD8B720360EBCC0D5C9AC145036A9BBFA0"
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using Confuser;
using Confuser.Core;
using Confuser.Core.Project;
using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;


namespace Confuser {
    
    
    /// <summary>
    /// EditRule
    /// </summary>
    public partial class EditRule : System.Windows.Window, System.Windows.Markup.IComponentConnector {
        
        
        #line 48 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Border Chrome;
        
        #line default
        #line hidden
        
        
        #line 58 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Grid Root;
        
        #line default
        #line hidden
        
        
        #line 72 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Label Bar;
        
        #line default
        #line hidden
        
        
        #line 79 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Grid Main;
        
        #line default
        #line hidden
        
        
        #line 94 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox patternBox;
        
        #line default
        #line hidden
        
        
        #line 113 "..\..\EditRule.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.ListBox list;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/Confuser;component/editrule.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\EditRule.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            this.Chrome = ((System.Windows.Controls.Border)(target));
            return;
            case 2:
            this.Root = ((System.Windows.Controls.Grid)(target));
            return;
            case 3:
            this.Bar = ((System.Windows.Controls.Label)(target));
            
            #line 72 "..\..\EditRule.xaml"
            this.Bar.MouseDown += new System.Windows.Input.MouseButtonEventHandler(this.Bar_MouseDown);
            
            #line default
            #line hidden
            return;
            case 4:
            
            #line 74 "..\..\EditRule.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.Close_Click);
            
            #line default
            #line hidden
            return;
            case 5:
            this.Main = ((System.Windows.Controls.Grid)(target));
            return;
            case 6:
            this.patternBox = ((System.Windows.Controls.TextBox)(target));
            return;
            case 7:
            this.list = ((System.Windows.Controls.ListBox)(target));
            return;
            case 8:
            
            #line 121 "..\..\EditRule.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.OK_Click);
            
            #line default
            #line hidden
            return;
            case 9:
            
            #line 122 "..\..\EditRule.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.Cancel_Click);
            
            #line default
            #line hidden
            return;
            }
            this._contentLoaded = true;
        }
    }
}

